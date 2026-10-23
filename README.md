# PHP Vulnerabilities: Azure WAF Mitigation Runbook

Advisory review date: **2026-10-24**.

This runbook separates recommendations for CVE-2026-109618, CVE-2026-109619, and CVE-2026-115560. Azure WAF provides temporary compensating controls, not a PHP vulnerability fix. The existing rule definitions and deployment scripts remain unchanged.

## Choose a Response

| Vulnerability | Relevant behavior | Recommended WAF response | Remaining risk |
| --- | --- | --- | --- |
| CVE-2026-109618 | Out-of-memory handling leaves partially initialized request state unsafe during cleanup. | Enforce conservative request/upload limits; optionally block multipart where it is unnecessary. Treat nesting rules as supplementary controls. | Small requests, multipart expansion, and application-specific allocations can still exhaust memory. Upgrade PHP. |
| CVE-2026-109619 | Request-owned state survives into a later request handled by the same worker. | Restrict the session upload-progress entry point using the existing baseline; optionally block multipart entirely. | Other stale-state producers and consumers are not covered. Upgrade PHP. |
| CVE-2026-115560 | Upload progress is enabled, the configured serializer is `php_binary` or `php_serialize`, and application code switches it to `php` before `session_start()`. | If PHP configuration cannot be changed, temporarily block multipart requests across the affected PHP scope. | WAF cannot establish the server-side prerequisites; alternate ingress and parsing differences must be addressed. Track the dedicated PHP fix. |

**Patch status:** PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12 contain fixes for CVE-2026-109618 and CVE-2026-109619. Use these or later supported patched releases, or verified vendor backports. Do not assume those releases also fix CVE-2026-115560: the October 23 notice says its full advisory will accompany the next regular bugfix release.

## Source Interpretation and Coverage

The [Microsoft upgrade and Azure WAF guidance](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623) calls for **request-side and response-side controls**, not just the three custom rules. Its October 22 revision supplies the cookie rewrite expression used below. PHP advisories remain authoritative for affected configurations and remediation.

The third-party [ikow/php2shell-poc repository](https://github.com/ikow/php2shell-poc/tree/31519e6d8a84dee1df1262961ed1bebb65accadd) is used as a test-design reference, pinned to commit `31519e6d8a84dee1df1262961ed1bebb65accadd`. Its chain names, reliability claims, and scanner results are research observations, not Azure protection guarantees or a one-to-one mapping to CVEs. Its serializer-mismatch chain is not proof of the precise CVE-2026-115560 runtime-switch prerequisite. Do not copy its ModSecurity rules directly into an Azure policy.

| Source observation | Operational consequence | What a passing WAF check does not prove |
| --- | --- | --- |
| Chains A/C use upload progress and require additional application/configuration conditions. | Test the default and actual configured progress field names; include filename-bearing multipart controls. | Blocking a marker does not establish that all injection or deserialization paths are closed. |
| Chain B requires attacker-controlled deserialization. | Keep patching and application review separate from upload controls. | A multipart block does not protect arbitrary application `unserialize()` calls. |
| Chain D concerns OOM during mod_php request startup. | Test size enforcement and supported framing without causing OOM; do not restrict mitigation to named upload routes. | A small accepted request or a rejected large request does not demonstrate memory safety. |
| Chain E describes a session-dependent producer followed by an early consumer on another PHP endpoint. | Cover all affected PHP routes, including extensionless and no-session endpoints; correlate worker failures separately. | A single-request test cannot reproduce or exclude cross-request worker-state exploitation. |
| Detection examples inspect filenames, response errors, and chunked framing. | Use supported Azure match variables, origin telemetry, and safe fixtures; verify framing after proxy normalization. | Absence of a visible `Transfer-Encoding` header or an error string is not proof of safety. |

Do not execute the repository's exploit or vulnerability scanner against production. Some checks intentionally exhaust memory, corrupt session state, or crash workers. A 502, timeout, or worker restart is an availability incident to investigate, not evidence of RCE or a successful mitigation.

## Preconditions and Read-Only Checks

Run examples from the repository root in Bash. Replace all placeholders. Use Azure CLI 2.75.0 or later and jq 1.6 or later; check that your installed CLI exposes the parameters shown below. Front Door commands require the `front-door` extension.

```bash
az version
az extension add --name front-door --upgrade
az login

SUBSCRIPTION='<subscription-id>'
AG_RG='<application-gateway-policy-resource-group>'
AG_POLICY='<existing-php-application-gateway-waf-policy>'
FD_RG='<front-door-policy-resource-group>'
FD_POLICY='<existing-php-front-door-waf-policy>'

az network application-gateway waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --name "$AG_POLICY" \
	--query '{id:id,settings:policySettings,rules:customRules,managed:managedRules,gateways:applicationGateways,listeners:httpListeners,paths:pathBasedRules}' \
	--output json

az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--query '{id:id,sku:sku,settings:policySettings,rules:customRules.rules,securityPolicies:securityPolicyLinks,endpoints:frontendEndpointLinks}' \
	--output json
```

Before any write:

- Confirm the effective policy covers only the intended PHP domains/routes, including extensionless routes. A nonempty association list does not prove all traffic uses that policy.
- Require an enabled policy in **Prevention** mode for enforcement. Changing the mode affects every applicable rule, so obtain approval first.
- Review earlier terminal `Allow` rules. Lower priority numbers run first; an earlier matching `Allow` can bypass the proposed controls.
- Block direct origin access and review alternate ingress/failover paths. WAF does not protect requests that bypass it.
- Back up the policy, inspect the proposed changes, and schedule a window without concurrent policy writers. CLI read-modify-write operations are not an atomic concurrency lock.
- Ensure request-side WAF diagnostic logs and origin access/error logs are available. The response rule `99006001` is an explicit exception: it produces neither WAF log entries nor hit counts. Readback confirms control-plane configuration, not data-plane enforcement.

The backup-only commands below use the repository tools and do not modify Azure. Each creates a separate restricted backup directory; record the printed paths.

```bash
bash azureapplicationgateway-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" \
	--policy-name "$AG_POLICY" --backup-only

bash azurefrontdoor-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" \
	--policy-name "$FD_POLICY" --backup-only
```

## CVE-2026-109618: Reduce OOM Exposure

### Recommended approach

Upgrade PHP first. If that must wait, constrain request processing before it reaches PHP. Keep the existing nesting rules in Log until legitimate traffic has been assessed; 20 levels is a policy threshold, not an exploit boundary. Turning them into Block does not eliminate this vulnerability.

For Application Gateway WAF_v2 with CRS 3.2 or a compatible newer engine, the following **optional write** enables body inspection and size enforcement. The example accepts at most 128 KB of non-file request data and a 32 MB file upload limit. These are illustrative business limits, not vulnerability-specific safe values. Do not raise a stricter existing limit just to match this example.

```bash
az network application-gateway waf-policy policy-setting update \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--state Enabled --mode Prevention \
	--request-body-check true \
	--request-body-enforcement true \
	--max-request-body-size-in-kb 128 \
	--request-body-inspect-limit-in-kb 128 \
	--file-upload-enforcement true \
	--file-upload-limit-in-mb 32

az network application-gateway waf-policy policy-setting list \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--output json
```

Request-body inspection depth, request size enforcement, and file upload limits are different controls. File content is treated separately from non-file request data; these settings do not impose a 128 KB total multipart request cap. Review the documented file-limit buffer as well. Restore previous settings individually from the backup if rolling back; deleting a custom rule will not restore policy settings.

Front Door does not expose the same Application Gateway size-setting parameters. Its documented 128 KB body-inspection boundary is not a configurable total decoded-request rejection limit. Do not rely on `Content-Length` alone or assume a custom size condition measures all uninspected bytes. If uploads are unnecessary, use the emergency multipart block below. Otherwise, require decoded-size, part-count, per-part header-count, input-count, and nesting limits at an upstream capable of enforcing them, or at the origin before PHP parsing.

### Required owner follow-up

If you cannot manage PHP configuration, escalate to the runtime owner. PHP documents administratively enforced `memory_limit=-1` as a partial mitigation, together with conservative `post_max_size` and resource isolation. Removing PHP's memory limit increases availability risk and must not be done without capacity review. Underlying allocation failures remain possible; do not substitute `RLIMIT_AS` or `RLIMIT_DATA`. WAF limits are not equivalent to these runtime changes.

## CVE-2026-109619: Restrict Upload Progress, Then Patch

### Recommended approach

The existing `BlockPhpSessionUploadProgress` rule already uses **Block**. It restricts multipart requests containing the default upload-progress marker; the two nesting rules do not cover all stale-state paths.

Use the existing deployment tools for the Microsoft baseline. They call Azure CLI, preview by default, preserve unrelated rules, and check policy state, priority conflicts, and earlier Allow rules. **The baseline includes all three existing rules**, not a CVE-specific complete fix. It keeps both nesting rules in Log.

```bash
bash azureapplicationgateway-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY"

bash azurefrontdoor-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY"
```

Only after reviewing each preview and the application impact, these **optional writes** apply the baseline:

```bash
bash azureapplicationgateway-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" --apply

bash azurefrontdoor-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" --apply
```

Verify the upload-progress rule through Azure CLI:

```bash
az network application-gateway waf-policy custom-rule show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--name BlockPhpSessionUploadProgress --output json

az network front-door waf-policy rule show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--name BlockPhpSessionUploadProgress --output json
```

Inventory the actual `session.upload_progress.name` across PHP pools/sites: the baseline uses the default `PHP_SESSION_UPLOAD_PROGRESS`. Custom names require separately reviewed coverage. Application Gateway uses parsed `PostArgs`; Front Door uses inspected `RequestBody`. Test a harmless request where only the field name contains the marker and the value is ordinary text. Neither matching model guarantees coverage of every encoding or oversized request.

### Required owner follow-up

Ask the runtime owner to disable `session.upload_progress.enabled` before request parsing and restart every worker. Do not rely on application `ini_set()` or FPM `.user.ini`. On PHP 8.5, disabling `fatal_error_backtraces` removes another confirmed path. Correct early configuration diagnostics and attacker-reachable fatal errors/timeouts. These measures remain partial: this CVE also involves non-upload state. A PHP update is the complete remediation.

## CVE-2026-115560: Emergency Multipart Containment

### Recommended approach

First determine whether the application has all three prerequisites listed in the response table. WAF cannot inspect the application's serializer configuration or runtime calls. Do not invent signatures for `ini_set`, `php_serialize`, or serialized payload syntax: the request need not contain those strings.

PHP's documented mitigation is `session.upload_progress.enabled=0`. If you cannot change it and cannot rule out the vulnerable combination, an emergency option is to block all declared `multipart/form-data` traffic across the affected PHP scope. This sacrifices legitimate uploads and multipart forms, but avoids dependence on the progress field name and its location in the inspected body.

The following are **optional writes to existing policies**, one example per platform. They add a separate rule; they do not edit the baseline rules. Use only PHP-scoped policies. On a shared policy, design and validate additional host/path conditions before applying; do not temporarily create a broad block and add scope later.

Confirm `EmergencyBlockPhpMultipart` does not already exist. The sample priorities `89` and `499` must be free and precede every Allow rule that could match the affected traffic. Being earlier than the baseline does not mean being earlier than all Allow rules. Stop on a collision rather than overwriting or automatically renumbering rules. Review rule quotas and existing conditions before applying.

### Application Gateway WAF_v2

The complete condition is supplied in the same create operation. The `negationConditon` spelling below follows the Application Gateway rule schema used by this repository.

```bash
az network application-gateway waf-policy custom-rule create \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--name EmergencyBlockPhpMultipart --priority 89 \
	--state Enabled --rule-type MatchRule --action Block \
	--match-conditions '[{"matchVariables":[{"variableName":"RequestHeaders","selector":"Content-Type"}],"operator":"Contains","negationConditon":false,"transforms":["Lowercase"],"matchValues":["multipart/form-data"]}]'

az network application-gateway waf-policy custom-rule show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--name EmergencyBlockPhpMultipart --output json
```

### Azure Front Door WAF

Front Door uses a different CLI and rule schema. The selector is expressed as `RequestHeader.Content-Type`; the full header condition is included at creation time.

```bash
az network front-door waf-policy rule create \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--name EmergencyBlockPhpMultipart --priority 499 \
	--disabled false --rule-type MatchRule --action Block \
	--match-variable RequestHeader.Content-Type \
	--operator Contains --values multipart/form-data --transforms Lowercase

az network front-door waf-policy rule show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--name EmergencyBlockPhpMultipart --output json
```

These header-based rules do not depend on body-inspection depth. They still depend on correct policy scope, precedence, propagation, and consistent header interpretation between WAF and PHP. They are not proof that the CVE is fully mitigated. If this uncertainty is unacceptable, temporarily deny external access to the affected PHP service using a separately approved isolation change.

### Roll Back Only the Emergency Rule

After verifying a dedicated PHP fix or the runtime mitigation, review the current rule and remove only the rule added above. These are **optional writes**. Do not run them if a rule with that name predates this change or has since been repurposed. Confirm deletion and retain the backup/change record. Existing baseline rules and policy settings remain in place.

```bash
az network application-gateway waf-policy custom-rule delete \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--name EmergencyBlockPhpMultipart

az network front-door waf-policy rule delete \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--name EmergencyBlockPhpMultipart
```

For baseline rollback, use the platform-specific tool documentation instead. Its full custom-rule restore can overwrite later changes and is not interchangeable with deleting this one emergency rule.

## Response-Side Defense in Depth

These measures supplement request filtering for PHP2Shell; they do not prevent corruption inside PHP, undo origin-side execution, or establish remediation of CVE-2026-115560. Patch every serving runtime and rebuild/redeploy affected container images: updating the host does not update PHP embedded in an image.

| Platform | Microsoft guidance as reviewed on October 24 | Verification requirement |
| --- | --- | --- |
| Front Door with supported managed DRS | Enable response rule `99006001` in `MS-ThreatIntel-Response-CVEs`, supported on DRS 2.0, 2.1, and 2.2. | Confirm actual SKU/ruleset availability and response behavior, not log hits. |
| Application Gateway v2 | Add a conditional response-header rewrite to remove the matching `Set-Cookie` header. | Confirm regex support, route association, and preservation of other cookies. |
| Application Gateway for Containers | Request-side custom rules only in the cited guidance; regex response rewrite is not supported. A managed response rule was announced for later. | Do not apply the Application Gateway v2 commands to this product or claim response protection is available. |

### Back Up Response Configuration Separately

The repository scripts restore **custom request rules only**. Their rollback does not restore Front Door managed-rule overrides, Application Gateway rewrite sets, route associations, or policy size settings. Keep the relevant snapshots and an approved, component-specific rollback record. The gateway resource group can differ from the WAF policy resource group.

These calls read Azure and write restricted local snapshots; they do not change Azure. Stop on any failed command or invalid/empty snapshot. Do not commit backups containing infrastructure details or response evidence to Git.

```bash
AG_GATEWAY_RG='<application-gateway-resource-group>'
AG_GATEWAY='<existing-application-gateway-v2>'
umask 077
RESPONSE_BACKUP=$(mktemp -d "${TMPDIR:-/tmp}/php2shell-response.XXXXXX")

az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--output json > "$RESPONSE_BACKUP/frontdoor-policy.json"
jq -e '.managedRules.managedRuleSets | type == "array"' "$RESPONSE_BACKUP/frontdoor-policy.json"

az network application-gateway show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_GATEWAY_RG" --name "$AG_GATEWAY" \
	--output json > "$RESPONSE_BACKUP/application-gateway.json"
jq -e '.id and .sku and (.requestRoutingRules | type == "array")' "$RESPONSE_BACKUP/application-gateway.json"

printf 'Response configuration snapshots: %s\n' "$RESPONSE_BACKUP"
```

### Front Door: Enable and Read Back 99006001

Microsoft says rollout is expected to finish on **October 28, 2026**. On this runbook's October 24 review date, do not assume the rule is available everywhere. It is **disabled by default** and takes effect only with the portal action **Block on anomaly**. The CLI rule action for anomaly scoring is `AnomalyScoring`; verify the resulting portal action as well. Do not substitute a normal `Block`, `Log`, or challenge action.

First inspect the actual managed rule definitions and policy. Front Door Standard's custom-rule capability does not imply access to managed DRS; use a supported SKU such as Premium. Do not replace or upgrade the current DRS just to run this example: a version migration needs its own exclusion/override review.

```bash
az network front-door waf-policy managed-rule-definition list \
	--subscription "$SUBSCRIPTION" --output json

az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--query '{sku:sku,settings:policySettings,managed:managedRules}' --output json
```

Locate `99006001` in group `MS-ThreatIntel-Response-CVEs` in the **already attached** `Microsoft_DefaultRuleSet` version 2.0, 2.1, or 2.2. If absent, unavailable, or rejected by the service, record response protection as **not available**, retain request containment, and check rollout with Microsoft. Do not manufacture a custom rule with the same ID.

The following is an **optional write**, after approval and backup. Use it only after confirming that the target override is absent and that the installed CLI's targeted add preserves existing groups/rules. If an override already exists, edit that entry through a reviewed merge or the portal rather than appending a duplicate. Preserve its exclusions and sensitivity; do not replace the entire `managedRules` collection.

```bash
az network front-door waf-policy managed-rules override add \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--type Microsoft_DefaultRuleSet \
	--rule-group-id MS-ThreatIntel-Response-CVEs --rule-id 99006001 \
	--disabled false --action AnomalyScoring

az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--query 'managedRules.managedRuleSets' --output json
```

Compare the full managed-rule collection with the snapshot: only the intended override should change. Confirm `enabledState=Enabled`, `action=AnomalyScoring`, the portal's **Block on anomaly** action, effective Enabled/Prevention policy, and the correct security-policy/domain/path bindings. Preserve/review the ruleset-level anomaly action separately; do not silently change it for all rules.

**Important:** Microsoft documents response sanitization, not the usual request-block response. Potentially malicious elements are removed while the remaining response is returned. **This rule generates no WAF log entries or hit counts.** Neither an absent `99006001` log nor a non-403 response establishes failure. Conversely, readback alone does not prove sanitization works. Use response differential evidence below; a generic invalid-cookie fixture is not guaranteed to trigger this proprietary managed signature.

Rollback must restore only the target override to its recorded prior state. If it did not previously exist, remove only the newly added override using the documented managed-rule override operation and confirm the group retains all unrelated entries. If it existed, restore its previous enabled state, action, exclusions, and sensitivity. Do not restore the entire policy over newer changes or disable the policy to undo one rule. Repeat functional tests and document the resulting loss of response protection.

### Application Gateway v2: Conditional Set-Cookie Rewrite

Use the following expression exactly as published in Microsoft's October 22 guidance, matching the **response** `Set-Cookie` value, not the request `Cookie` header:

```text
^PHPSESSID=(?:[a-zA-Z0-9-]|%2[Cc])*(?:[^a-zA-Z0-9;%-]|%(?!2[Cc]))+[a-zA-Z0-9-]*[^;]+;
```

It targets the default, case-sensitive `PHPSESSID` cookie name. Inventory the real `session.name`; custom names require a separately reviewed expression and regression tests. This is a targeted heuristic, not a general session-ID validator. Keep the published pattern's edge cases visible in tests; do not treat every nonmatch as safe. The expression contains negative lookahead, while the general rewrite documentation recommends RE2-compatible patterns and notes engine limitations. Validate service acceptance and actual matching on the target gateway/engine. If rejected or ineffective, stop and seek Microsoft guidance rather than silently weakening the pattern.

Plan the association before writing. A Basic routing rule can have only **one** rewrite set; path-based routing uses the URL path map's default rewrite and individual path-rule rewrites. If a set is already attached, add a uniquely named rule with a free sequence to that set only after reviewing every route that shares it, or clone/merge through the existing IaC process. Never replace an existing binding with an empty/new set and discard its other rewrites.

The following **optional write** assumes an existing, reviewed rewrite set and a free rule name/sequence. Adding to an attached set changes traffic immediately. `headerValueMatcher` selects the matching member when several `Set-Cookie` headers are present; an empty header value expresses deletion. A condition followed by an unqualified `Set-Cookie` delete can remove unrelated cookies, so do not omit the matcher. Confirm that your CLI exposes `--response-header-configurations` and preserves the matcher in readback; otherwise use the portal/approved ARM configuration, not `--response-headers Set-Cookie=` as a fallback.

```bash
AG_REWRITE_SET='<existing-reviewed-rewrite-set>'
AG_REWRITE_RULE='RemovePhp2ShellSessionCookie'
AG_REWRITE_SEQUENCE='<free-sequence>'
PHP_COOKIE_PATTERN='^PHPSESSID=(?:[a-zA-Z0-9-]|%2[Cc])*(?:[^a-zA-Z0-9;%-]|%(?!2[Cc]))+[a-zA-Z0-9-]*[^;]+;'

AG_COOKIE_CONDITIONS=$(jq -cn --arg pattern "$PHP_COOKIE_PATTERN" \
	'[{variable:"http_resp_Set-Cookie",pattern:$pattern,ignoreCase:false,negate:false}]')
AG_COOKIE_ACTIONS=$(jq -cn --arg pattern "$PHP_COOKIE_PATTERN" \
	'[{headerName:"Set-Cookie",headerValue:"",headerValueMatcher:{pattern:$pattern,ignoreCase:false,negate:false}}]')

az network application-gateway rewrite-rule create \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_GATEWAY_RG" --gateway-name "$AG_GATEWAY" \
	--rule-set-name "$AG_REWRITE_SET" --name "$AG_REWRITE_RULE" --sequence "$AG_REWRITE_SEQUENCE" \
	--conditions "$AG_COOKIE_CONDITIONS" --response-header-configurations "$AG_COOKIE_ACTIONS"

az network application-gateway rewrite-rule show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_GATEWAY_RG" --gateway-name "$AG_GATEWAY" \
	--rule-set-name "$AG_REWRITE_SET" --name "$AG_REWRITE_RULE" --output json

az network application-gateway show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_GATEWAY_RG" --name "$AG_GATEWAY" \
	--query '{state:provisioningState,rewrites:rewriteRuleSets,routes:requestRoutingRules,paths:urlPathMaps}' \
	--output json
```

For a route with no existing set, first prepare and verify a complete set using the portal or existing IaC workflow, then associate it with the actual PHP route. For **Basic routing only**, the association operation is shown below. It is an optional write, not needed when the correct set is already attached. For path-based routing, configure the intended default/path-rule association instead; do not assume this Basic example covers the path map.

```bash
AG_BASIC_RULE='<reviewed-basic-php-routing-rule>'
az network application-gateway rule update \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_GATEWAY_RG" --gateway-name "$AG_GATEWAY" \
	--name "$AG_BASIC_RULE" --rewrite-rule-set "$AG_REWRITE_SET"
```

Require successful gateway provisioning and read back the full set and route/path-map references. Compare with the snapshot, including rule order and any later rule that could reintroduce a deleted header. Removing the matched header also removes its `Path`, `Domain`, `Secure`, `HttpOnly`, and `SameSite` attributes; if choosing replacement instead, replace the **whole** value deliberately and verify those attributes. Do not insert a fake reusable session identifier.

For rollback, delete only the newly added rewrite rule from the existing set after confirming its current definition and ownership. If a new set/binding was introduced, restore the exact previous Basic/path/default binding first, verify traffic, and remove the new set only when no route references it. Preserve all pre-existing rewrites. Gateway snapshots are review/restore inputs, not a safe whole-resource PUT payload. Repeat login, cookie, and routing checks after rollback.

## Data-Plane Validation

### Capture Harmless Request Controls

Allow configuration propagation, then test only an authorized, non-destructive staging endpoint. Use a disposable test account/session if authentication is required. Do not send probes to an endpoint that executes business transactions. Disable caching on the test route; a client `Cache-Control` header alone does not guarantee Front Door bypasses cache. Do not disable WAF, add a bypass Allow, or open the origin publicly for testing.

Run the following in Bash after replacing `TEST_URL` with an HTTPS URL **without an existing query string**. Each call saves response headers/body/status/timing without following redirects or reusing returned cookies. A redirect is not proof that the eventual PHP route was inspected; test that route separately. Keep the evidence directory private, redact sensitive headers before sharing, and apply your retention policy. `curl` deliberately does not use `--fail`, because an expected WAF block may be a 4xx response; stop and investigate transport errors.

```bash
TEST_URL='https://<authorized-staging-php-host>/<test-route>'
PROBE_ID="php2shell-$(date -u +%Y%m%dT%H%M%SZ)-$$"
umask 077
EVIDENCE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/php2shell-validation.XXXXXX")

probe() {
	local case_name="$1"
	shift
	curl --silent --show-error --connect-timeout 5 --max-time 20 \
		--dump-header "$EVIDENCE_DIR/${case_name}.headers" \
		--output "$EVIDENCE_DIR/${case_name}.body" \
		--write-out 'status=%{http_code}\nremote=%{remote_ip}\ntime=%{time_total}\n' \
		--header "X-WAF-Validation-ID: ${PROBE_ID}-${case_name}" \
		--header 'Cache-Control: no-cache' \
		"$@" "${TEST_URL}?waf_validation=${PROBE_ID}-${case_name}" \
		> "$EVIDENCE_DIR/${case_name}.meta"
}

probe ordinary-get
probe ordinary-form --data-urlencode 'ordinary_field=harmless'
probe ordinary-multipart --form-string 'ordinary_field=harmless'
probe progress-name --form-string 'PHP_SESSION_UPLOAD_PROGRESS=harmless'
probe progress-value --form-string 'ordinary_field=PHP_SESSION_UPLOAD_PROGRESS'
probe empty-file --form-string 'ordinary_field=harmless' \
	--form 'upload=@/dev/null;filename=waf-validation.txt;type=text/plain'

NESTED19='field'
for ((level=0; level<19; level++)); do NESTED19+='[x]'; done
NESTED20="${NESTED19}[x]"
probe form19 --data-urlencode "${NESTED19}=harmless"
probe form20 --data-urlencode "${NESTED20}=harmless"
probe multipart19 --form-string "${NESTED19}=harmless"
probe multipart20 --form-string "${NESTED20}=harmless"

printf 'Probe ID: %s\nEvidence: %s\n' "$PROBE_ID" "$EVIDENCE_DIR"
```

Use the URL query marker, UTC time window, request method, client address, and returned Azure tracking/request identifiers to correlate logs. An arbitrary client header is not guaranteed to appear in WAF logs; configure staging origin access logging for the marker if necessary. A request-side Block should have the intended WAF rule/action and no corresponding origin request. First verify origin-log completeness with a permitted control; absence in incomplete logs is not evidence.

### Request Acceptance Matrix

Record each case per host, actual PHP route, and WAF hop. An accepted control means the expected application response, not necessarily HTTP 200. An unrelated managed-rule block is not a pass for the custom rule under test. If a declared expectation is not met, mark a coverage gap and keep stronger containment; do not rename a failure as success because another request was blocked.

| Case | Baseline alone | Emergency multipart block active |
| --- | --- | --- |
| Ordinary GET and shallow URL-encoded form | No match from these three rules; application behavior remains usable. | Same; any separate body-size or managed rule still applies. |
| Ordinary multipart and harmless empty file | No intended baseline match; verify legitimate upload behavior. | `EmergencyBlockPhpMultipart` blocks before PHP. |
| Default progress marker only in field name, ordinary value | Require `BlockPhpSessionUploadProgress` Block; if parsed `PostArgs` does not cover the name on the target engine, document the gap. A value-only match does not close it. | Emergency Block, independent of field-name parsing. |
| Marker only in field value | Characterize broad substring matching and false positives; this is not proof the progress-name case works. | Emergency Block. |
| Actual custom `session.upload_progress.name` | Not guaranteed by the default marker rule; separately reviewed coverage is required. | Emergency Block. |
| URL-encoded nesting 19 / 20 levels | No nesting match at 19; `PhpFormNesting20` Log at 20, not Block. | Same, because this is not multipart. |
| Multipart nesting 19 / 20 levels without progress token | No nesting match at 19; `PhpMultipartNesting20` Log at 20 where the platform parses/matches the name as configured. Document engine gaps. | Emergency Block at either depth; this masks the nesting rule. |
| Content-Type case variation and legitimate boundary parameters | Check actual platform normalization; do not assume `BeginsWith` and `Contains` have identical semantics. | Emergency Block for accepted multipart variants. |
| Marker near/beyond inspected-body boundary, within approved staging safety limits | Record actual inspection and parsing coverage; no blanket full-body guarantee. | Header-based Block should not depend on token location. |
| Approved non-file and file sizes just below/above their separate limits | For Application Gateway, prove the configured enforcement layer rejects over-limit requests before PHP; include the documented upload buffer. | Multipart rejection may mask size enforcement; validate limits separately in an isolated policy. |
| Small valid HTTP/1.1 chunked multipart and HTTP/2 multipart, where supported | Observe edge-to-origin normalization; a visible `Transfer-Encoding` condition alone is not a complete control. Never combine conflicting framing headers. | Require multipart rejection or an identifiable stricter edge rejection before PHP; attribute it correctly. |
| Extensionless/no-session PHP routes and alternative domains | Same coverage expectations as named upload routes. | Same emergency Block throughout the affected PHP scope. |

Do not use huge allocations, excessive part/header counts, serialized objects, executable filenames, heap sprays, or multi-request stale-state triggers for this acceptance test. Use at most small, bounded controls; stop on unexpected latency, 5xx responses, worker restarts, or resource pressure. Size/inspection-boundary tests require an agreed staging memory budget and stop threshold. Never increase limits just to reach a test boundary. Keep destructive PoC evaluation, if separately authorized, in a disposable isolated lab with no production connectivity or data.

When Front Door fronts Application Gateway, an outer Block can hide a missing inner control. Test each through an approved private staging path or isolated equivalent topology, without weakening production origin restrictions. Also verify the combined path. Record each layer's policy/resource ID and result separately.

### Response Differential Matrix

Use an isolated, access-restricted staging fixture that emits **fixed harmless** response headers and a constant body, without invoking PHP sessions, accepting arbitrary header values, or exposing secrets. An owner-provided static fixture is sufficient for rewrite tests; do not publish a vulnerable PHP page. Obtain the origin baseline from inside the authorized network or from controlled fixture output, not by opening public origin access. Disable route caching and remove the fixture after validation.

For the Application Gateway expression above, test these literal cookie values as separate `Set-Cookie` header lines. They contain no exploit or leaked memory:

| Origin response header value | Expected published-pattern result |
| --- | --- |
| `PHPSESSID=abc-123; Path=/; HttpOnly; Secure; SameSite=Lax` | Preserved, including all attributes. |
| `PHPSESSID=abc%2C123; Path=/` and `PHPSESSID=abc%2c123; Path=/` | Preserved; encoded comma is explicitly permitted by the pattern. |
| `PHPSESSID=abc!fixture123; Path=/; HttpOnly` | Pattern-positive: remove this complete header. |
| `PHPSESSID=abc%41fixture123; Path=/` | Pattern-positive: remove; demonstrates that this is not a general URL-decoding validator. |
| `OTHER=keep; Path=/; Secure` alongside the pattern-positive PHP cookie | Preserve `OTHER` exactly; delete only the matching PHP header. Repeat with reversed header order and multiple PHP cookies. |
| No `Set-Cookie`, or only nonmatching cookies | Response unchanged. |
| `phpSessid=abc!fixture123; Path=/` or an actual custom cookie name | Not covered by the default case-sensitive name; require separate review, not an automatic pass. |
| `PHPSESSID=abc!;` or `PHPSESSID=abc!fixture123` without a semicolon | Published-pattern nonmatches; record the heuristic's coverage limits. Do not claim all malformed session cookies are removed. |

Fetch the fixture through the tested WAF path with the same evidence-capture options as the request controls. Compare individual raw `Set-Cookie` lines, unchanged body/status and other headers, and expected origin reachability. Do not comma-join cookies: `Expires` attributes can themselves contain commas. Test normal login/logout, session continuity, redirects, cookie attributes, and gateway-affinity cookies using disposable accounts.

These fixture expectations validate **Application Gateway rewrite matching**, not Front Door's private managed signature. For `99006001`, confirm availability, enabled state, supported DRS/action, and propagation, then use a Microsoft-approved benign response test case or support-assisted validation. Compare the authorized baseline and protected responses; do not enable a dangerous PoC to obtain a positive sample. Without a known-positive managed-rule sample, record **configuration verified; response efficacy not yet verified**. No WAF log or hit-count evidence is expected for `99006001`; the Application Gateway rewrite is also not a request-side WAF rule hit.

### Evidence and Release Gate

- Save policy/gateway IDs, SKU/engine/ruleset versions, UTC test window, source revision, approved changes, pre/post snapshots, route bindings, probe markers, and redacted response captures.
- For request controls, retain WAF rule/action and access-log correlation plus origin evidence; for response controls, retain header/body differential evidence. Do not interpret the standard access logs as response-header captures.
- Review origin PHP/FPM/Apache error logs for memory exhaustion, session destruction failures, worker crashes/restarts, and unexplained 5xx responses. These are investigation signals, not by themselves proof of exploitation. Standard access logs usually do not contain multipart bodies, so searching them for the progress marker is not a reliable absence test.
- Verify direct-origin and alternate/failover ingress restrictions, expected health probes, login/upload compatibility, and the independent inner/outer WAF paths. Do not broaden exclusions or insert early Allow rules just to pass regression tests.
- Perform the component-specific rollback rehearsal in staging, then repeat the controls. Record restored functionality **and** lost protection. Do not roll back production containment before patch/runtime mitigation is verified or an approved replacement is in place.

Promote only with reviewed request-control evidence, verified response behavior where a valid test exists, acceptable regression results, a tested rollback, and a named owner/deadline for PHP remediation. Track unavailable rules or unverified managed-response efficacy explicitly as residual risk; a control-plane `Succeeded`, local regex test, or PoC scanner verdict is not an exploitation-resistance certificate.

The commands in this document have not been deployed against a live Azure policy. Local syntax checks do not validate service acceptance, propagation, matching semantics, or protection against exploitation.

## Repository Tools

- [Application Gateway WAF tool and operational safeguards](azureapplicationgateway-waf/README.md)
- [Front Door WAF tool and operational safeguards](azurefrontdoor-waf/README.md)
- [Threat-hunting queries](threat-hunting/README.md)

## Official References

- [PHP advisories and October 23 serializer prerequisites](https://www.php.net/archive/2026.php)
- [CVE-2026-109618: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Microsoft PHP2Shell WAF baseline and limitations](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684)
- [Microsoft upgrade guidance, response rule rollout, and cookie rewrite](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623)
- [Application Gateway custom-rule CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy/custom-rule?view=azure-cli-latest)
- [Application Gateway policy-setting CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy/policy-setting?view=azure-cli-latest)
- [Application Gateway request and upload limits](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits)
- [Application Gateway rewrite behavior, multiple Set-Cookie selection, and regex limitations](https://learn.microsoft.com/en-us/azure/application-gateway/rewrite-http-headers-url)
- [Application Gateway rewrite-rule CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/rewrite-rule?view=azure-cli-latest)
- [Application Gateway rewrite ARM schema and headerValueMatcher](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2025-01-01/applicationgateways)
- [Application Gateway routing-rule association CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/rule?view=azure-cli-latest)
- [Front Door custom-rule CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/rule?view=azure-cli-latest)
- [Front Door available managed-rule definitions CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/managed-rule-definition?view=azure-cli-latest)
- [Front Door managed-rule override CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/managed-rules/override?view=azure-cli-latest)
- [Front Door DRS, anomaly scoring, and SKU availability](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs)
- [Front Door inspection-boundary comparison](https://learn.microsoft.com/en-us/azure/frontdoor/high-availability#scenario-1-traffic-manager-failover-from-azure-front-door-to-an-application-gateway-waf)

## Third-Party Research References

- [ikow PoC README at the reviewed revision](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/README.md)
- [ikow chain analysis, prerequisites, and cross-request observations](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/docs/ANALYSIS.md)
- [ikow ModSecurity indicators, not an Azure-importable ruleset](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/detection/modsecurity.conf)
