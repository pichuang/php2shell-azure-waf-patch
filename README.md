# Azure Front Door and Application Gateway: PHP WAF Mitigation Runbook

## TL;DR

> **Back up the existing WAF configuration before any deployment or change.** Follow [Shared Preparation](#shared-preparation) to export the policy, preserving custom rules, managed-rule overrides, and policy settings. If changing Application Gateway response rewrites, also back up the gateway's rewrite sets and route bindings. Continue only after confirming that the backups are complete and readable and a rollback plan is ready; do not deploy if backup fails or is incomplete.

1. **Apply temporary protection for your platform:** Use the Azure CLI steps for [Front Door](#azure-front-door-waf) or [Application Gateway](#azure-application-gateway-waf_v2), preserve existing rules, and confirm PHP route scope, Enabled/Prevention state, and earlier Allow rules. Apply the upload-progress baseline and assess platform-specific size limits and response protection; keep nesting rules in Log initially.
2. **Consider emergency containment if PHP cannot be changed immediately:** If the vulnerable CVE-2026-115560 configuration cannot be excluded, temporarily block multipart across the affected PHP scope after approval. This interrupts legitimate uploads and multipart forms and does not fully remediate all three vulnerabilities.
3. **Validate in staging before production deployment:** Follow [Data-Plane Validation](#data-plane-validation) to verify request blocking, response behavior, login/upload impact, and rehearse [component rollback](#rollback-by-component). Successful configuration readback does not prove enforcement; Front Door response rule 99006001 provides no WAF logs or hit counts.
4. **Pursue PHP remediation in parallel:** WAF is temporary containment. Have the runtime owner confirm the applicable fix or mitigation for each CVE and update every serving runtime and container image; do not assume releases fixing the first two vulnerabilities also fix CVE-2026-115560.

## What Happened

Use the block's copy button to paste this update into Teams or another messaging app.

```text
[PHP2Shell risk and recommended response | Information reviewed: 2026-10-24]

What happened?
PHP announced three related vulnerabilities (CVE-2026-109618, CVE-2026-109619, and CVE-2026-115560). In plain terms, under specific conditions, PHP can mishandle memory exhaustion, data left behind by a previous request, or upload-progress and session data. An attacker who meets the relevant conditions could crash the website service or potentially execute unauthorized code on the server. Not every PHP website meets the same conditions; versions, settings, and application behavior still need assessment. This notice does not establish that we have been compromised.

Recommended actions:
1. Before any deployment, back up the existing Azure WAF configuration, confirm the backup is complete and readable, and prepare a rollback plan. If changing Application Gateway response rewrites, also back up rewrite rules and route bindings. Do not deploy if backup fails.
2. In parallel, have system owners inventory PHP versions, settings, and container images, confirm the applicable fix or mitigation for each vulnerability, and schedule updates. Do not assume versions fixing the first two vulnerabilities also fix CVE-2026-115560.
3. Add temporary protection through Azure Front Door or Application Gateway WAF, preserve existing rules, confirm coverage of the affected PHP routes, and restrict direct origin access that bypasses WAF. Configure size limits and response protection according to platform capabilities and availability.
4. If PHP cannot be changed immediately and the vulnerable CVE-2026-115560 configuration cannot be excluded, consider an approved temporary block on multipart requests, commonly used for file uploads, across affected PHP routes. This interrupts legitimate uploads and some forms; assess business impact first.
5. Verify blocking, login/upload impact, and rollback in staging before production deployment. Successful configuration does not prove enforcement. WAF reduces risk but does not replace PHP remediation or guarantee protection against every exploitation path.

Please have the responsible owners report affected sites and versions, backup and validation results, the planned change window, upload interruption impact, remediation owners, and deadlines. Mark unconfirmed items as pending; do not report planned controls as completed.
```

Advisory review date: **2026-10-24**.

Start with the platform you operate. The primary workflow uses Azure CLI directly for CVE-2026-109618, CVE-2026-109619, and CVE-2026-115560; repository scripts are an optional alternative at the end. Azure WAF provides temporary compensating controls, not a PHP vulnerability fix. The existing rule definitions and deployment scripts remain unchanged. Run only the commands for your platform; if both products protect the application, configure and validate each layer independently.

## Recommended Configuration

| Vulnerability | Azure Front Door WAF | Application Gateway WAF_v2 |
| --- | --- | --- |
| CVE-2026-109618 | Block multipart where the upload interruption is acceptable; otherwise require upstream/origin limits before PHP parsing. Front Door's 128 KB inspection depth is not a total request-size enforcement setting. | Enable request-body inspection, non-file body-size enforcement, and file-upload enforcement with approved conservative limits. Block multipart when stronger containment is needed. |
| CVE-2026-109619 | Apply the upload-progress baseline; use a separate multipart Block for stronger containment. Add managed response rule `99006001` when available. | Apply the upload-progress baseline; use a separate multipart Block for stronger containment. Add the conditional response-cookie rewrite. |
| CVE-2026-115560 | If runtime mitigation cannot be applied and the vulnerable configuration cannot be excluded, temporarily Block multipart across the affected PHP routes. | Same: temporarily Block multipart across the affected PHP routes. |

**Operational choice:** If PHP settings cannot be changed, emergency multipart blocking is the strongest request-side option shown here, but interrupts legitimate uploads and multipart forms. Response controls are additional PHP2Shell defense in depth, not a dedicated fix for all three CVEs. Keep nesting rules in **Log** until traffic has been assessed; changing them to Block does not complete remediation.

- [Azure Front Door configuration](#azure-front-door-waf): baseline, emergency Block, managed response protection, and readback.
- [Application Gateway configuration](#azure-application-gateway-waf_v2): size enforcement, baseline, emergency Block, response rewrite, and readback.
- [Validation](#data-plane-validation), [rollback](#rollback-by-component), and [vulnerability/source details](#vulnerability-details-and-remediation) follow the configuration sections.

## Shared Preparation

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

Back up directly with Azure CLI before changing custom rules, policy size settings, managed-rule overrides, or rewrite sets/bindings. The following calls read Azure and write restricted local snapshots; they do not change Azure. Run only the applicable `az ... show` and `jq` pair. Stop on a failed command or invalid/empty snapshot. Use restricted storage, do not commit backups to Git, and do not overwrite later changes with a whole-resource restore. Keep the printed backup directory available for the platform steps below.

```bash
AG_GATEWAY_RG='<application-gateway-resource-group>'
AG_GATEWAY='<existing-application-gateway-v2>'
umask 077
RESPONSE_BACKUP=$(mktemp -d "${TMPDIR:-/tmp}/php2shell-response.XXXXXX")

az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--output json > "$RESPONSE_BACKUP/frontdoor-policy.json"
jq -e '.managedRules.managedRuleSets | type == "array"' "$RESPONSE_BACKUP/frontdoor-policy.json"

az network application-gateway waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --name "$AG_POLICY" \
	--output json > "$RESPONSE_BACKUP/application-gateway-policy.json"
jq -e '.id and .policySettings' "$RESPONSE_BACKUP/application-gateway-policy.json"

az network application-gateway show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_GATEWAY_RG" --name "$AG_GATEWAY" \
	--output json > "$RESPONSE_BACKUP/application-gateway.json"
jq -e '.id and .sku and (.requestRoutingRules | type == "array")' "$RESPONSE_BACKUP/application-gateway.json"

printf 'Configuration snapshots: %s\n' "$RESPONSE_BACKUP"
```

## Azure Front Door WAF

Use an existing policy scoped to the affected PHP domains/routes. All writes below require the shared preparation, backup, and approval. Require effective **Enabled + Prevention** settings and verify the security-policy/domain/path binding before relying on a Block. Do not replace the policy or its custom-rule collection.

### 1. CVE-2026-109619: Apply the Upload-Progress Baseline

Use Azure CLI to read the current policy, then merge the existing [Front Door rule definitions](azurefrontdoor-waf/php2shell-rules.json) with jq. This JSON file is configuration data, not an executable script. The baseline contains three rules: upload progress **Block** at priority 500 and nesting **Log** at priorities 501/502. Do not pass the baseline file alone to `--custom-rules`: that replaces the collection and can remove unrelated rules.

The following preparation makes no Azure changes. It requires Enabled/Prevention, preserves unrelated rules and other custom-rule properties, and rejects an existing name/priority collision rather than overwriting it. If baseline rules already exist, inspect their definitions and use a separately reviewed update; do not delete them just to rerun this first-install example. Review earlier Allow rules and rule quotas before proceeding. Stop on any error; do not run the apply block unless every preparation check succeeds.

```bash
az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--output json > "$RESPONSE_BACKUP/frontdoor-baseline.before.json" &&
jq -e '.policySettings.enabledState == "Enabled" and .policySettings.mode == "Prevention"' \
	"$RESPONSE_BACKUP/frontdoor-baseline.before.json" &&
jq -e --slurpfile baseline azurefrontdoor-waf/php2shell-rules.json '
	(.customRules // {}) as $custom |
	($custom.rules // []) as $existing |
	$baseline[0].rules as $new |
	if any($existing[]; . as $old |
		any($new[]; .name == $old.name or .priority == $old.priority))
	then error("Existing rule name or priority: stop and review")
	else $custom + {rules: ($existing + $new)} end
' "$RESPONSE_BACKUP/frontdoor-baseline.before.json" \
	> "$RESPONSE_BACKUP/frontdoor-custom-rules.merged.json" &&
jq . "$RESPONSE_BACKUP/frontdoor-custom-rules.merged.json"
```

Review the **complete** merged JSON, including earlier terminal Allow rules and all unrelated entries. Immediately before applying, re-read and compare the policy. Stop if this check fails or reports a difference; rebuild the plan from the changed policy instead. This detects observed drift but is not an atomic If-Match lock, so retain the no-concurrent-writers window.

```bash
az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--output json > "$RESPONSE_BACKUP/frontdoor-baseline.preapply.json" &&
diff -u <(jq -S . "$RESPONSE_BACKUP/frontdoor-baseline.before.json") \
	<(jq -S . "$RESPONSE_BACKUP/frontdoor-baseline.preapply.json")
```

**Optional write after approval:** apply only the reviewed merged custom-rule collection. Do not change managed rules, settings, or SKU as part of this step. Stop on any failed command; read back and compare all custom rules, not just the upload-progress rule.

```bash
az network front-door waf-policy update \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--custom-rules "@$RESPONSE_BACKUP/frontdoor-custom-rules.merged.json" &&
az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--query '{settings:policySettings,custom:customRules,managed:managedRules}' --output json

az network front-door waf-policy rule show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--name BlockPhpSessionUploadProgress --output json
```

Confirm that all previous rules/settings/managed rules remain unchanged and that the three baseline rules have the expected actions and conditions. Readback is not a data-plane test. The Front Door baseline matches the default marker in inspected `RequestBody`. Confirm the actual `session.upload_progress.name`, test field-name-only matching, and do not assume coverage beyond the inspection boundary. For stronger containment, use step 2.

### 2. CVE-2026-115560 and Stronger Containment: Block Multipart

If the vulnerable PHP configuration cannot be excluded and you cannot disable upload progress at runtime, temporarily block declared `multipart/form-data` across the affected PHP scope. This also reduces multipart exposure relevant to CVE-2026-109618 and CVE-2026-109619, but does not close every path. Legitimate multipart forms/uploads will stop working.

**Optional write:** the name must be new and priority `499` must be free and earlier than **every** matching terminal Allow. Review quotas. On a shared policy, include approved host/path conditions in the initial rule instead of applying this unscoped example. Do not overwrite an existing rule.

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

### 3. CVE-2026-109618: Request-Size Limitations

Front Door does **not** expose Application Gateway's request-body/upload enforcement flags. Its 128 KB body-inspection boundary is not a configurable total decoded-request rejection cap. Do not invent a Front Door equivalent of `--max-request-body-size-in-kb`, rely on `Content-Length` alone, or assume a custom condition measures all uninspected bytes.

If multipart uploads can be interrupted, use step 2. Otherwise, require decoded-size, part-count, per-part header-count, input-count, and nesting limits at a capable upstream/origin **before PHP parsing**. If no such limit is available, record the gap and escalate isolation/patching; the WAF policy alone cannot establish OOM safety.

### 4. Additional PHP2Shell Protection: Enable Response Rule 99006001

Microsoft expects rollout to finish on **October 28, 2026**. As of this runbook's October 24 review, verify availability rather than assuming the rule exists. It is **disabled by default**, in group `MS-ThreatIntel-Response-CVEs`, on DRS 2.0/2.1/2.2. Front Door Standard's custom-rule capability does not imply managed-DRS support; use a supported SKU such as Premium. Do not upgrade/replace an attached DRS just to run this example.

```bash
az network front-door waf-policy managed-rule-definition list \
	--subscription "$SUBSCRIPTION" --output json

az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--query '{sku:sku,settings:policySettings,managed:managedRules}' --output json
```

Locate `99006001` in the **already attached** `Microsoft_DefaultRuleSet` version. If unavailable or rejected, retain request containment, record response protection as **not available**, and check rollout with Microsoft. Do not manufacture a custom rule with the same ID.

**Optional write:** after backup and approval, use the following only if the target override is absent and the installed CLI's targeted add preserves existing groups/rules. If it exists, use a reviewed merge or edit that rule in the portal rather than appending a duplicate. Preserve exclusions, sensitivity, and all other overrides.

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

Compare the full managed-rule collection against the snapshot: only the intended override should change. Confirm `enabledState=Enabled`, `action=AnomalyScoring`, and the portal action **Block on anomaly**, which Microsoft requires for this response rule. Do not substitute normal `Block`, `Log`, or challenge actions. Review the ruleset-level anomaly action separately without silently changing it for all rules.

The rule sanitizes potentially malicious response elements while returning the remaining content; do not expect a request-side 403. It generates **no WAF log entries or hit counts**. Use the response differential validation below; readback and a generic invalid-cookie fixture alone do not prove this proprietary signature works. This is defense in depth, not proof of remediation for any of the three CVEs.

## Azure Application Gateway WAF_v2

Use an existing PHP-scoped WAF policy and the actual gateway's routing/rewrite resources. The gateway resource group may differ from the policy resource group. All writes below require shared preparation, backup, and approval. These are **Application Gateway v2** recommendations, not Application Gateway for Containers commands.

### 1. CVE-2026-109618: Enforce Request and Upload Limits

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

### 2. CVE-2026-109619: Apply the Upload-Progress Baseline

The existing `BlockPhpSessionUploadProgress` rule already uses **Block**. It restricts multipart requests containing the default upload-progress marker; the two nesting rules do not cover all stale-state paths.

Read and merge with Azure CLI and jq using the existing [Application Gateway rule definitions](azureapplicationgateway-waf/php2shell-rules.json). **The baseline includes all three rules**, not a CVE-specific complete fix: priority 90 Block and priorities 91/92 Log. Do not pass this file alone to `--custom-rules`, which replaces the custom-rule collection. The preparation below retains unrelated entries and stops on name/priority collisions. Existing baseline installations require a reviewed update rather than this first-install example. Check earlier Allow rules and quotas. Stop on any error before continuing.

```bash
az network application-gateway waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --name "$AG_POLICY" \
	--output json > "$RESPONSE_BACKUP/application-gateway-baseline.before.json" &&
jq -e '.policySettings.state == "Enabled" and .policySettings.mode == "Prevention"' \
	"$RESPONSE_BACKUP/application-gateway-baseline.before.json" &&
jq -e --slurpfile baseline azureapplicationgateway-waf/php2shell-rules.json '
	(.customRules // []) as $existing |
	$baseline[0] as $new |
	if any($existing[]; . as $old |
		any($new[]; .name == $old.name or .priority == $old.priority))
	then error("Existing rule name or priority: stop and review")
	else $existing + $new end
' "$RESPONSE_BACKUP/application-gateway-baseline.before.json" \
	> "$RESPONSE_BACKUP/application-gateway-custom-rules.merged.json" &&
jq . "$RESPONSE_BACKUP/application-gateway-custom-rules.merged.json"
```

Review the complete merged JSON and application impact. Re-read the policy immediately before applying; stop on failure or any difference. This snapshot is taken **after** step 1's approved size-setting changes, so it does not reuse a stale pre-change policy. The check is not an atomic concurrency lock.

```bash
az network application-gateway waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --name "$AG_POLICY" \
	--output json > "$RESPONSE_BACKUP/application-gateway-baseline.preapply.json" &&
diff -u <(jq -S . "$RESPONSE_BACKUP/application-gateway-baseline.before.json") \
	<(jq -S . "$RESPONSE_BACKUP/application-gateway-baseline.preapply.json")
```

**Optional write after approval:** update only the reviewed merged custom-rule array, then read back settings, managed rules, and all custom rules to check for unintended changes. Confirm all original entries remain, with the three baseline actions/conditions as expected. Stop on any command failure.

```bash
az network application-gateway waf-policy update \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --name "$AG_POLICY" \
	--custom-rules "@$RESPONSE_BACKUP/application-gateway-custom-rules.merged.json" &&
az network application-gateway waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --name "$AG_POLICY" \
	--query '{settings:policySettings,custom:customRules,managed:managedRules}' --output json

az network application-gateway waf-policy custom-rule show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--name BlockPhpSessionUploadProgress --output json
```

Inventory the actual `session.upload_progress.name` across PHP pools/sites: the baseline uses the default `PHP_SESSION_UPLOAD_PROGRESS`. Custom names require separately reviewed coverage. Application Gateway uses parsed `PostArgs`. Test a harmless request where only the field name contains the marker and the value is ordinary text; do not assume coverage of every encoding or oversized request.

### 3. CVE-2026-115560 and Stronger Containment: Block Multipart

PHP's documented mitigation is `session.upload_progress.enabled=0`. If you cannot change it and cannot rule out the vulnerable combination, an emergency option is to block all declared `multipart/form-data` traffic across the affected PHP scope. This sacrifices legitimate uploads and multipart forms, but avoids dependence on the progress field name and its location in the inspected body.

The following is an **optional write to an existing policy**. It adds a separate rule without editing the baseline rules. Use only a PHP-scoped policy. On a shared policy, design and validate additional host/path conditions before applying; do not temporarily create a broad block and add scope later.

Confirm `EmergencyBlockPhpMultipart` does not already exist. Priority `89` must be free and precede every Allow rule that could match the affected traffic. Being earlier than the baseline does not mean being earlier than all Allow rules. Stop on a collision rather than overwriting or automatically renumbering rules. Review rule quotas and existing conditions before applying.

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

These header-based rules do not depend on body-inspection depth. They still depend on correct policy scope, precedence, propagation, and consistent header interpretation between WAF and PHP. They are not proof that the CVE is fully mitigated. If this uncertainty is unacceptable, temporarily deny external access to the affected PHP service using a separately approved isolation change.

### 4. Additional PHP2Shell Protection: Rewrite Suspicious Set-Cookie

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

## Rollback by Component

After verifying a dedicated PHP fix or the runtime mitigation, review the current emergency rule and remove only the rule added in this change. Run only your platform's command below. These are **optional writes**; do not run them if that name predates this change or has since been repurposed. Confirm deletion and retain the backup/change record. Existing baseline rules and policy settings remain in place.

```bash
az network front-door waf-policy rule delete \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--name EmergencyBlockPhpMultipart

az network application-gateway waf-policy custom-rule delete \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--name EmergencyBlockPhpMultipart
```

| Changed component | Required rollback |
| --- | --- |
| Baseline custom rules | Compare the current collection with the platform's `*-baseline.before.json`. For a first install, remove only the three newly added, still-owned baseline rules using the platform custom-rule delete commands after verifying their current definitions; retain unrelated/later changes. A full custom-rule restore can overwrite later changes. The optional tools document that alternative, not a single-rule rollback. |
| Application Gateway body/upload settings | Restore the previous individual settings from `application-gateway-policy.json`; a custom-rule restore does not cover them. |
| Front Door response override | Restore only `99006001` to its prior state/action/exclusions/sensitivity. If previously absent, remove only the new override and preserve all other group entries. Do not remove the entire DRS or disable WAF. |
| Gateway response rewrite/binding | Remove only the added rule; if a new binding/set was introduced, restore the precise prior Basic/default/path binding before removing an unreferenced new set. Preserve other rewrites. |

Re-read the changed component, repeat login/upload/routing and WAF checks, and record both restored behavior and lost protection. Do not perform a blind whole-policy/gateway restore over concurrent changes.

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

## Vulnerability Details and Remediation

| Vulnerability | Relevant behavior | Remaining risk despite WAF controls |
| --- | --- | --- |
| CVE-2026-109618 | Out-of-memory handling leaves partially initialized request state unsafe during cleanup. | Small requests, multipart expansion, and application-specific allocations can still exhaust memory. WAF size/nesting limits do not prove memory safety. |
| CVE-2026-109619 | Request-owned state survives into a later request handled by the same worker. | Upload progress is one entry point; other stale-state producers and consumers are not covered by a marker or multipart block. |
| CVE-2026-115560 | Upload progress is enabled, the initial serializer is `php_binary` or `php_serialize`, and application code switches it to `php` before `session_start()`. | WAF cannot establish these server-side prerequisites. Do not invent request signatures for `ini_set`, `php_serialize`, or serialized syntax: those strings need not be present. |

**Patch status:** PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12 contain fixes for CVE-2026-109618 and CVE-2026-109619. Use these or later supported patched releases, or verified vendor backports. Do not assume those releases also fix CVE-2026-115560: the October 23 notice says its full advisory will accompany the next regular bugfix release. Patch every serving runtime and rebuild/redeploy affected images; updating a host does not update PHP inside containers.

If you cannot manage PHP settings, escalate to the runtime owner. For CVE-2026-109618, PHP documents administratively enforced `memory_limit=-1` as a partial mitigation with conservative `post_max_size` and resource isolation. Removing PHP's memory limit increases availability risk and requires capacity review. Underlying allocation failures remain possible; do not substitute `RLIMIT_AS` or `RLIMIT_DATA`. WAF limits are not equivalent to these runtime changes.

For upload-progress paths and CVE-2026-115560, ask the owner to disable `session.upload_progress.enabled` **before parsing** and restart every worker. Do not rely on application `ini_set()` or FPM `.user.ini`. For CVE-2026-109619 on PHP 8.5, disabling `fatal_error_backtraces` removes another confirmed path. Correct early configuration diagnostics and attacker-reachable fatal errors/timeouts. These steps do not replace the PHP update for non-upload stale state.

Response sanitization cannot prevent corruption inside PHP or undo execution at the origin. Application Gateway for Containers is a separate product: the cited guidance provides request-side custom rules only, without regex response rewriting; a managed response rule was announced for later. Do not apply the v2 rewrite commands or Front Door rule ID to it.

## Source Interpretation and Coverage

The [Microsoft upgrade and Azure WAF guidance](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623) calls for **request-side and response-side controls**, not just the three custom rules. Its October 22 revision supplies the cookie rewrite expression above. PHP advisories remain authoritative for affected configurations and remediation.

The third-party [ikow/php2shell-poc repository](https://github.com/ikow/php2shell-poc/tree/31519e6d8a84dee1df1262961ed1bebb65accadd) is used as a test-design reference, pinned to commit `31519e6d8a84dee1df1262961ed1bebb65accadd`. Its chain names, reliability claims, and scanner results are research observations, not Azure protection guarantees or a one-to-one mapping to CVEs. Its serializer-mismatch chain is not proof of the precise CVE-2026-115560 runtime-switch prerequisite. Do not copy its ModSecurity rules directly into an Azure policy.

| Source observation | Operational consequence | What a passing WAF check does not prove |
| --- | --- | --- |
| Chains A/C use upload progress and require additional application/configuration conditions. | Test the default and actual configured progress field names; include filename-bearing multipart controls. | Blocking a marker does not establish that all injection or deserialization paths are closed. |
| Chain B requires attacker-controlled deserialization. | Keep patching and application review separate from upload controls. | A multipart block does not protect arbitrary application `unserialize()` calls. |
| Chain D concerns OOM during mod_php request startup. | Test size enforcement and supported framing without causing OOM; do not restrict mitigation to named upload routes. | A small accepted request or a rejected large request does not demonstrate memory safety. |
| Chain E describes a session-dependent producer followed by an early consumer on another PHP endpoint. | Cover all affected PHP routes, including extensionless and no-session endpoints; correlate worker failures separately. | A single-request test cannot reproduce or exclude cross-request worker-state exploitation. |
| Detection examples inspect filenames, response errors, and chunked framing. | Use supported Azure match variables, origin telemetry, and safe fixtures; verify framing after proxy normalization. | Absence of a visible `Transfer-Encoding` header or an error string is not proof of safety. |

Do not execute the repository's exploit or vulnerability scanner against production. Some checks intentionally exhaust memory, corrupt session state, or crash workers. A 502, timeout, or worker restart is an availability incident to investigate, not evidence of RCE or a successful mitigation.

## Repository Tools

### Optional Script Workflow

The Azure CLI steps above are the primary procedure. The repository scripts are an alternative for deploying the same baseline, not an additional required step; do not run both workflows to install it twice. They preview by default, merge unrelated rules, detect priority/earlier-Allow issues, and support backup, apply, and rollback workflows. Read the platform documentation before using them.

Run only your platform's commands. `--backup-only` reads Azure and saves a restricted local backup; the command without an action flag previews; `--apply` is an **optional Azure write** after review and approval.

```bash
bash azurefrontdoor-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" --backup-only

bash azurefrontdoor-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY"

bash azurefrontdoor-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" --apply
```

```bash
bash azureapplicationgateway-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" --backup-only

bash azureapplicationgateway-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY"

bash azureapplicationgateway-waf/mitigate-php2shell.sh \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" --apply
```

The scripts' restore covers **custom request rules only**, not policy size settings, managed-rule overrides, or gateway rewrite sets/bindings. Keep the separate CLI snapshots and component-specific rollback plan for those changes. Their backups have their own format; do not pass the raw CLI snapshots above to a script rollback operation.

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
- [Front Door policy update and custom-rules JSON input](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy?view=azure-cli-latest#az-network-front-door-waf-policy-update)
- [Application Gateway policy update and custom-rules JSON input](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy?view=azure-cli-latest#az-network-application-gateway-waf-policy-update)
- [Front Door available managed-rule definitions CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/managed-rule-definition?view=azure-cli-latest)
- [Front Door managed-rule override CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/managed-rules/override?view=azure-cli-latest)
- [Front Door DRS, anomaly scoring, and SKU availability](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs)
- [Front Door inspection-boundary comparison](https://learn.microsoft.com/en-us/azure/frontdoor/high-availability#scenario-1-traffic-manager-failover-from-azure-front-door-to-an-application-gateway-waf)

## Third-Party Research References

- [ikow PoC README at the reviewed revision](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/README.md)
- [ikow chain analysis, prerequisites, and cross-request observations](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/docs/ANALYSIS.md)
- [ikow ModSecurity indicators, not an Azure-importable ruleset](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/detection/modsecurity.conf)
