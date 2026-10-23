# azureapplicationgateway-waf

English | [Traditional Chinese](README.zh-TW.md)

Use Azure CLI to add three PHP2Shell mitigation rules to an **existing Azure Application Gateway WAF policy dedicated to PHP applications**. The workflow matches the Front Door tool in this repository: preview and back up by default, write only with an explicit `--apply`, and support standalone backups and rollback of the complete custom rules collection. The tool does not create policies or change gateway, listener, or path associations or other settings.

The rules follow the **Application Gateway** definitions in the [Microsoft article (October 21, 2026, version 2.0)](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684), rather than copying the Front Door rules directly. This is a temporary mitigation; complete remediation still requires upgrading to a patched PHP version.

## Structure and Rules

```text
azureapplicationgateway-waf/
  .gitignore
  mitigate-php2shell.sh
  php2shell-rules.json
  README.md
  README.zh-TW.md
  tests/
    test-mitigate-php2shell.sh
```

Rules are defined in [php2shell-rules.json](php2shell-rules.json). The two conditions in each rule are combined with AND.

| Priority | Name | Action | Match Criteria |
| --- | --- | --- | --- |
| 90 | BlockPhpSessionUploadProgress | Block | A multipart header and `php_session_upload_progress` in PostArgs, matched case-insensitively |
| 91 | PhpFormNesting20 | Log | A URL-decoded form body containing parameter names with at least 20 levels of bracket nesting |
| 92 | PhpMultipartNesting20 | Log | Multipart PostArgs field names with at least 20 levels of bracket nesting |

`Log` records matches without blocking and continues evaluating subsequent rules. The 20-level threshold is an application policy choice, not a guaranteed boundary for the vulnerability. Consider changing Log to Block only after validating compatibility with legitimate traffic. This tool does not automatically escalate actions.

Differences from Front Door: Application Gateway priorities range from 1 to 100, so this tool uses the article's priorities 90-92 rather than 500-502. `customRules` is an array, using `state`, `matchVariables`, `matchValues`, `Regex`, and the API's original spelling `negationConditon`. The session and multipart rules use `PostArgs`; the multipart regex targets parsed field names rather than the full Content-Disposition text.

## Prerequisites

- Bash 3.2 or later, Azure CLI 2.75.0 or later, and jq 1.6 or later, on macOS, Linux, or Azure Cloud Shell Bash.
- Application Gateway WAF_v2 and an existing WAF policy. The policy itself does not have Front Door's SKU field. The tool neither changes nor infers the associated gateway's SKU.
- Azure authentication and read permission on the target policy. Applying changes also requires write permission, such as Network Contributor at an appropriate scope. The service determines whether Azure Policy permits the update.
- Adding mitigation rules requires `policySettings.state: Enabled`, `mode: Prevention`, `provisioningState: Succeeded`, and at least one association reference in `applicationGateways`, `httpListeners`, or `pathBasedRules`.
- Manually confirm that the effective policy covers only affected PHP domains and paths, including extensionless paths handled by PHP. Listener or path policies can override gateway-level policies; the existence of an association alone does not mean that all traffic is protected.

This command group is built into Azure CLI and does not require the `front-door` extension. The script does not automatically install dependencies, sign in, or switch the global subscription.

```bash
az login
az version
jq --version
chmod +x mitigate-php2shell.sh tests/test-mitigate-php2shell.sh
```

## Usage

Run from this directory, replacing the three target parameters:

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>'
```

The default is `--dry-run`. After reading and validating the resource ID and data structure, the tool immediately creates a persistent backup, then displays added and skipped rules, the complete merged result, and any blockers to applying changes. Preview remains available for Disabled, Detection, or unassociated policies. Conflicts or quota violations cause a nonzero exit while preserving the original snapshot. A backup failure stops the operation.

After reviewing scope, false-positive risks, and changes, add `--apply` to the same parameters to apply them. To back up existing rules only, use `--backup-only`; it cannot be combined with `--dry-run`, `--apply`, or `--rollback`.

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>' \
  --apply
```

Use `--backup-dir '/secure/path'` to change the backup root. The default is `backups/POLICY_NAME/php2shell-TIMESTAMP.SUFFIX/` beside the script. Each run uses a separate directory without overwriting previous backups. Backup directories have permission 700 and files default to 600. Backups may contain sensitive settings; custom directories are not automatically added to Git ignore rules. `--help` does not require authentication.

### Force Apply

After reviewing the risks, use `--force --apply` to bypass pre-apply warnings, including Disabled, Detection, non-Succeeded provisioning states (including Updating, Failed, or unknown states), missing associations, and earlier Allow rules:

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>' \
  --force --apply
```

Warnings are still displayed, without an interactive confirmation prompt. `--force` alone or with `--dry-run` still previews without writing. The backup manifest's `force` field records whether this option was specified. `--force` applies only to adding mitigation rules and cannot be combined with `--backup-only` or `--rollback`. Use `--force-rollback` to overwrite subsequent changes during rollback.

**Forcing a write does not mean the mitigation is effective:** the script does not enable the policy, switch to Prevention, create associations, or remove Allow rules. Azure may still reject updates to a policy that is already updating or in another invalid state. Authentication and target validation, rule format checks, name and priority conflicts, quotas, backups, pre-write drift checks, and post-write verification cannot be bypassed. Service failures still cause a nonzero exit without automatic rollback.

### Update Safeguards

- Preserves existing non-target custom rules, managed rules, tags, location, policy settings, and associations. Does not modify `requestBodyCheck`.
- Skips identical rules, tolerating null values, default state and transforms, and empty selectors. If all rules are identical, no write occurs. Different content under the same name or case-insensitive name collisions stop the operation. A manually escalated Block action is never downgraded to Log.
- Stops on priority conflicts at 90, 91, or 92 without renumbering. Checks for duplicate names and priorities, a maximum of 100 rules, priorities from 1 to 100, and at most 10 conditions per rule. Front Door's five-regex-rule limit does not apply.
- An earlier enabled Allow rule blocks applying changes by default; `--force` can bypass this check. Other earlier terminating actions are shown with their complete conditions for review. Disabled Allow rules do not block applying changes.
- Lists all pre-apply issues, current values (`null` when missing), and required values. Does not automatically enable the policy, switch modes, or adjust associations.
- Backs up first, then rereads the policy. Any content or etag drift stops the operation. A single `waf-policy update --custom-rules @file` writes the entire array without creating transient rules one at a time.
- This CLI update command does not support `--no-wait`. After the update returns, the tool runs `wait --updated --interval 10 --timeout 600`, then reads back and compares rules and non-target settings. The 600-second timeout applies only to the wait phase, not the entire CLI update.
- Update failures, wait timeouts, or read-back mismatches cause a nonzero exit while preserving backups, without automatic rollback. Check the actual Azure state rather than retrying blindly.

**Concurrent write limitation:** rereading before an update is not an atomic If-Match lock. The CLI may also read and then write internally. A race remains between the final check and the write; schedule a change window with no other policy writers.

## Backups and Rollback

| Backup File | Contents |
| --- | --- |
| original-policy.json | Original full policy for comparison, not restored in its entirety |
| original-custom-rules.json | Complete pre-operation custom rules array; the rollback target |
| merged-custom-rules.json | Expected array to write; identical to the original rules for a standalone backup |
| added-rules.json | Rules added by this operation; an empty array for standalone backups and rollbacks |
| manifest.json | Resource ID, timestamp, operation, mode, rollback source, and verification status |
| verified-after.json | Post-write read-back result; absent if this stage was not reached |

`controlPlaneVerified: true` is set only after complete post-write verification succeeds. This field remains false for previews and standalone backups; that does not indicate backup failure. Use only complete, trusted, unmodified backup directories produced by this tool. Front Door backups are incompatible.

Use the same three target parameters with `--rollback` to preview a rollback, then add `--apply` after reviewing it:

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>' \
  --rollback './backups/<existing-php-waf-policy>/php2shell-TIMESTAMP.SUFFIX'
```

Rollback restores the **complete custom rules collection** from before that operation, rather than merely removing priorities 90-92. All other current settings remain unchanged. The tool first checks resource IDs in the manifest and original policy, the array structure, and content consistency. If current rules already match the snapshot, no write occurs.

Current rules must match the expected merged result in the source backup; otherwise rollback is refused. Only an explicit `--force-rollback --apply` overwrites subsequent changes. Forced rollback does not bypass resource checks, backup validation, current-state checks, or pre-write drift checks. Omit `--apply` to preview a forced rollback first.

Rollback is allowed only when the current provisioning state is Succeeded or Failed, regardless of Disabled, Detection, or missing associations. A new backup of the current state is created before rollback without changing the source snapshot. If needed, this new backup can restore the rules that existed before rollback. Failures do not trigger cascading retries or automatic rollback.

Normally, use the backup from the relevant apply operation. A successfully completed dry-run backup can also be used when actual rules match its expected result. A snapshot from a preview that failed early does not represent a completed merge. Standalone backups cannot predict later changes, so restoring changed rules from them usually requires `--force-rollback`. Unverified backups left after update timeouts can also be used, but first confirm that Azure is no longer updating. Unknown or partial results require manual review before forcing restoration.

To preserve rules added later while removing only those added by this operation, manually compare `added-rules.json` with the latest read-back result. Do not directly overwrite Azure with an entire old snapshot.

## Post-Apply Verification and Limitations

```bash
az network application-gateway waf-policy show \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --name '<existing-php-waf-policy>' \
  --query 'customRules[?priority >= `90` && priority <= `92`]' \
  --output json
```

Control-plane success does not mean data-plane propagation has completed. After settings take effect, use an authorized test environment to test legitimate requests, harmless multipart controls, forms containing the session token, and form and multipart fields with 19, 20, and 21 levels of nesting. Check each rule's name, action, timestamp, and request correlation details in WAF logs. Do not rely on HTTP 200 or 403 alone. Verify actual traffic after rollback as well.

This tool does not create diagnostic settings. Without WAF logs, data-plane verification is incomplete. Offline tests use jq's regex engine and do not replace verification of actual WAF matching, PostArgs parsing, or propagation.

Legitimate session upload progress usage and deeply nested parameters can cause false positives. Body and file inspection are limited by engine version, policy settings, inspection size, and content type. PostArgs covers only content that WAF can parse and expose for inspection; protection is not guaranteed for every encoding or large file. Do not apply Front Door's fixed 128 KB boundary to Application Gateway. Traffic that reaches the backend directly, bypassing the gateway, is not protected by this policy and must be restricted separately. These three rules are not a complete vulnerability fix; PHP must still be upgraded.

## Local Tests

```bash
/bin/bash -n mitigate-php2shell.sh
/bin/bash -n tests/test-mitigate-php2shell.sh
./tests/test-mitigate-php2shell.sh
shellcheck mitigate-php2shell.sh
shellcheck --exclude=SC2016 tests/test-mitigate-php2shell.sh
```

Tests use a strict mock `az` to check Application Gateway commands and rule fields. They cover previews, backups, merges, reruns, conflicts, quotas, Allow rules, states and associations at each level, rollback, corrupted backups, drift, update/wait/verification failures, and regex boundaries, without calling the real Azure CLI. SC2016 is excluded only for the test script because fixtures deliberately use single quotes to preserve jq variables.

Official references: [CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy?view=azure-cli-latest), [custom rules](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/custom-waf-rules-overview), and [request body and file size limits](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits).