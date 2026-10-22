#!/bin/bash
set -euo pipefail

mock_az() {
    printf '%s\n' "$*" >> "$MOCK_DIR/calls"
    case "${1:-} ${2:-} ${3:-} ${4:-}" in
        'version --output json ')
            jq -n --arg version "${MOCK_VERSION:-2.75.0}" '{"azure-cli": $version}' ;;
        'extension show --name front-door')
            [[ "${MOCK_FAILURE:-}" != extension ]] || return 1
            printf '{"name":"front-door"}\n' ;;
        'account show --subscription '*)
            [[ "${MOCK_FAILURE:-}" != login ]] || return 1
            printf '{"id":"11111111-1111-1111-1111-111111111111","state":"Enabled"}\n' ;;
        'network front-door waf-policy '*)
            operation=$4
            shift 4
            payload=''
            has_subscription=0
            has_group=0
            has_policy=0
            has_timeout=0
            has_no_wait=0
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --subscription) [[ "$2" == 11111111-1111-1111-1111-111111111111 ]]; has_subscription=1; shift 2 ;;
                    --resource-group) [[ "$2" == test-rg ]]; has_group=1; shift 2 ;;
                    --policy-name) [[ "$2" == php-policy ]]; has_policy=1; shift 2 ;;
                    --custom-rules) payload=${2#@}; [[ "$2" == @* ]]; shift 2 ;;
                    --no-wait) has_no_wait=1; shift ;;
                    --timeout) [[ "$2" == 600 ]]; has_timeout=1; shift 2 ;;
                    --interval) [[ "$2" == 10 ]]; shift 2 ;;
                    --updated|--only-show-errors) shift ;;
                    --output) [[ "$2" == json || "$2" == none ]]; shift 2 ;;
                    *) printf '未預期的 Azure 參數: %s\n' "$1" >&2; return 90 ;;
                esac
            done
            [[ "$has_subscription$has_group$has_policy" == 111 ]] || return 91
            case "$operation" in
                show)
                    [[ "${MOCK_FAILURE:-}" != read ]] || return 1
                    shows=$(< "$MOCK_DIR/shows")
                    shows=$((shows + 1))
                    printf '%s\n' "$shows" > "$MOCK_DIR/shows"
                    if [[ "${MOCK_FAILURE:-}" == drift && "$shows" == 2 ]]; then
                        jq '.etag = "concurrent-update"' "$MOCK_DIR/policy.json"
                    elif [[ "${MOCK_FAILURE:-}" == verify && -f "$MOCK_DIR/submitted.json" ]]; then
                        jq '.customRules.rules[0].action = "Allow"' "$MOCK_DIR/policy.json"
                    elif [[ "${MOCK_FAILURE:-}" == unrelated && -f "$MOCK_DIR/submitted.json" ]]; then
                        jq '.tags.owner = "unexpected"' "$MOCK_DIR/policy.json"
                    else
                        jq . "$MOCK_DIR/policy.json"
                    fi ;;
                update)
                    [[ -n "$payload" && "$has_no_wait" == 1 ]] || return 92
                    cp "$payload" "$MOCK_DIR/submitted.json"
                    [[ "${MOCK_FAILURE:-}" != update ]] || return 1
                    jq --slurpfile merged "$payload" '
                        .customRules = $merged[0] | .etag = "after" | .provisioningState = "Succeeded"
                        | .customRules.rules |= map(
                            .rateLimitDurationInMinutes = (.rateLimitDurationInMinutes // 1)
                            | .rateLimitThreshold = (.rateLimitThreshold // null)
                            | .groupBy = (.groupBy // [])
                            | .matchConditions |= map(.selector = (.selector // null) | .transforms = (.transforms // [])))
                    ' "$MOCK_DIR/policy.json" > "$MOCK_DIR/next.json"
                    mv "$MOCK_DIR/next.json" "$MOCK_DIR/policy.json" ;;
                wait)
                    [[ "$has_timeout" == 1 && "${MOCK_FAILURE:-}" != timeout ]] ;;
                *) return 93 ;;
            esac ;;
        *) printf '未預期的 Azure 呼叫: %s\n' "$*" >&2; return 94 ;;
    esac
}

if [[ "${0##*/}" == az ]]; then
    mock_az "$@"
    exit
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/php2shell-tests.XXXXXX")
trap 'rm -rf -- "$temp_dir"' EXIT
mkdir "$temp_dir/bin"
ln -s "$root/tests/test-mitigate-php2shell.sh" "$temp_dir/bin/az"
export PATH="$temp_dir/bin:$PATH"
export AZURE_CONFIG_DIR="$temp_dir/azure"
export MOCK_DIR MOCK_FAILURE MOCK_VERSION
arguments=(--subscription test-subscription --resource-group test-rg --policy-name php-policy)
passed=0

new_case() {
    case_name=$1
    MOCK_DIR=$(mktemp -d "$temp_dir/case.XXXXXX")
    MOCK_FAILURE=''
    MOCK_VERSION=2.75.0
    printf '0\n' > "$MOCK_DIR/shows"
    : > "$MOCK_DIR/calls"
    jq -n --slurpfile desired "$root/php2shell-rules.json" '
        {
          id: "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-rg/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/php-policy",
          name: "php-policy", type: "Microsoft.Network/frontdoorWebApplicationFirewallPolicies",
          location: "Global", sku: {name: "Premium_AzureFrontDoor"}, etag: "before",
          provisioningState: "Succeeded", resourceState: "Enabled", tags: {owner: "existing"},
          policySettings: {enabledState: "Enabled", mode: "Prevention", requestBodyCheck: "Disabled"},
          managedRules: {managedRuleSets: [{ruleSetType: "Microsoft_DefaultRuleSet", ruleSetVersion: "2.1"}]},
          securityPolicyLinks: [{id: "/subscriptions/test/securityPolicies/php"}],
          frontendEndpointLinks: [], customRules: {rules: []}
        }
        | '"${2:-.}" > "$MOCK_DIR/policy.json"
}

write_count() {
    awk '/^network front-door waf-policy update / {count++} END {print count+0}' "$MOCK_DIR/calls"
}

check_run() {
    expected_exit=$1
    expected_writes=$2
    message=$3
    shift 3
    before_writes=$(write_count)
    actual_exit=0
    /bin/bash "$root/mitigate-php2shell.sh" "${arguments[@]}" --backup-dir "$MOCK_DIR/backups" "$@" \
        > "$MOCK_DIR/output" 2>&1 || actual_exit=$?
    after_writes=$(write_count)
    if [[ "$actual_exit" != "$expected_exit" || "$((after_writes - before_writes))" != "$expected_writes" ]] \
        || ! grep -Fq -- "$message" "$MOCK_DIR/output"; then
        printf '失敗: %s (exit=%s, writes=%s)\n' "$case_name" "$actual_exit" "$((after_writes - before_writes))" >&2
        /bin/cat "$MOCK_DIR/output" >&2
        exit 1
    fi
    passed=$((passed + 1))
    printf '通過: %s\n' "$case_name"
}

new_case '獨立備份不受同名衝突、Detection 或 Allow 影響' '.policySettings.mode = "Detection" | .customRules.rules = [($desired[0].rules[1] | .action = "Allow")]'
check_run 0 0 '既有 custom rules 備份完成' --backup-only
backup=$(find "$MOCK_DIR/backups" -name manifest.json -print)
jq -e '.operation == "backup"' "$backup" >/dev/null
jq -e --slurpfile before "$MOCK_DIR/policy.json" '. == $before[0].customRules' "${backup%/*}/original-custom-rules.json" >/dev/null

new_case '備份與套用模式互斥'
check_run 1 0 '不可與' --backup-only --apply

new_case '預設僅預覽'
check_run 0 0 '僅預覽'
backup=$(find "$MOCK_DIR/backups/php-policy" -name manifest.json -print)
jq -e '.mode == "dry-run" and .controlPlaneVerified == false' "$backup" >/dev/null
jq -e '.rules == []' "${backup%/*}/original-custom-rules.json" >/dev/null
jq -e '.rules | length == 3' "${backup%/*}/merged-custom-rules.json" >/dev/null
[[ ! -f "${backup%/*}/verified-after.json" ]]
case_name='明確 dry-run 重跑保留每次快照'
check_run 0 0 '僅預覽' --dry-run
[[ $(find "$MOCK_DIR/backups/php-policy" -name manifest.json | awk 'END {print NR}') == 2 ]]
jq -e '.rules == []' "${backup%/*}/original-custom-rules.json" >/dev/null
dry_run_backup=${backup%/*}
case_name='dry-run 後套用緩解規則'
check_run 0 1 '讀回驗證完成' --apply
case_name='直接使用 dry-run 備份回滾套用結果'
check_run 0 1 '完整 custom rules 已還原' --rollback "$dry_run_backup" --apply
jq -e '.customRules.rules == []' "$MOCK_DIR/policy.json" >/dev/null
jq -e '.mode == "dry-run" and .controlPlaneVerified == false' "$dry_run_backup/manifest.json" >/dev/null

new_case '規則衝突的 dry-run 也先備份' '.customRules.rules = [($desired[0].rules[0] | .action = "Log")]'
check_run 1 0 '同名規則內容不同' --dry-run
backup=$(find "$MOCK_DIR/backups/php-policy" -name manifest.json -print)
jq -e --slurpfile before "$MOCK_DIR/policy.json" '. == $before[0].customRules' "${backup%/*}/original-custom-rules.json" >/dev/null

new_case 'dry-run 備份失敗即停止'
printf 'blocked\n' > "$MOCK_DIR/blocked"
check_run 1 0 '備份' --dry-run --backup-dir "$MOCK_DIR/blocked/subdir"

new_case '自訂根目錄仍以 policy 名稱分組'
check_run 0 0 '僅預覽' --dry-run --backup-dir "$MOCK_DIR/custom root"
[[ $(find "$MOCK_DIR/custom root/php-policy" -name manifest.json | awk 'END {print NR}') == 1 ]]

new_case 'policy 名稱不可作為路徑穿越'
check_run 1 0 'policy-name' --policy-name ../other --dry-run

new_case '空集合一次套用，容忍 Azure 回傳的預設欄位'
check_run 0 1 '讀回驗證完成' --apply
jq -e '.rules | length == 3 and [.[].priority] == [500,501,502]' "$MOCK_DIR/submitted.json" >/dev/null
backup=$(find "$MOCK_DIR/backups" -name manifest.json -print)
[[ -n "$backup" && -f "${backup%/*}/verified-after.json" ]]
jq -e '(.resourceId | endswith("/php-policy")) and .controlPlaneVerified == true' "$backup" >/dev/null
[[ $(stat -f '%Lp' "${backup%/*}" 2>/dev/null || stat -c '%a' "${backup%/*}") == 700 ]]

case_name='相同規則重跑零寫入'
check_run 0 0 '無需更新' --apply

case_name='回滾預覽零寫入'
check_run 0 0 '回滾僅預覽' --rollback "${backup%/*}"
[[ $(find "$MOCK_DIR/backups/php-policy" -name manifest.json | awk 'END {print NR}') == 2 ]]
jq -e '.controlPlaneVerified == true' "$backup" >/dev/null
case_name='回滾還原空集合'
check_run 0 1 '回滾完成' --rollback "${backup%/*}" --apply
jq -e '.rules == []' "$MOCK_DIR/submitted.json" >/dev/null
case_name='回滾重跑零寫入'
check_run 0 0 '無需回滾' --rollback "${backup%/*}" --apply

new_case '保留舊規則與其餘設定' '.customRules.rules = [($desired[0].rules[0] | .name = "Existing" | .priority = 200 | .action = "Log")]'
check_run 0 1 '讀回驗證完成' --apply
jq -e '.rules | length == 4 and .[0].name == "Existing" and .[0].priority == 200' "$MOCK_DIR/submitted.json" >/dev/null

new_case '部分規則已存在' '.customRules.rules = [$desired[0].rules[1]]'
check_run 0 1 '讀回驗證完成' --apply
jq -e 'length == 2 and all(.[]; .name != "PhpFormNesting20")' "$MOCK_DIR"/backups/php-policy/*/added-rules.json >/dev/null

new_case '同名異內容不覆寫' '.customRules.rules = [($desired[0].rules[1] | .action = "Block")]'
check_run 1 0 '同名規則內容不同' --apply

new_case '名稱大小寫碰撞不新增重複規則' '.customRules.rules = [($desired[0].rules[0] | .name = "blockphpsessionuploadprogress")]'
check_run 1 0 '同名規則內容不同' --apply

new_case 'priority 衝突' '.customRules.rules = [($desired[0].rules[0] | .name = "Other")]'
check_run 1 0 'priority 衝突' --apply

new_case '既有 priority 重複' '.customRules.rules = [($desired[0].rules[0] | .name = "Other" | .priority = 100), ($desired[0].rules[1] | .name = "Another" | .priority = 100)]'
check_run 1 0 'priority 重複' --apply

new_case '既有名稱重複' '.customRules.rules = [($desired[0].rules[0] | .priority = 100), ($desired[0].rules[0] | .priority = 101)]'
check_run 1 0 '名稱或 priority 重複' --apply

new_case 'custom rules 配額超限' '.customRules.rules = [range(1;99) as $index | $desired[0].rules[0] | .name = ("Existing" + ($index | tostring)) | .priority = $index | .action = "Log"]'
check_run 1 0 '配額' --apply

new_case '剛好 100 條規則' '.customRules.rules = [range(1;98) as $index | $desired[0].rules[0] | .name = ("Existing" + ($index | tostring)) | .priority = $index | .action = "Log"]'
check_run 0 1 '讀回驗證完成' --apply

new_case 'Regex rules 配額超限' '.customRules.rules = [range(1;5) as $index | $desired[0].rules[1] | .name = ("Regex" + ($index | tostring)) | .priority = $index]'
check_run 1 0 '配額' --apply

new_case '剛好 5 條 Regex rules' '.customRules.rules = [range(1;4) as $index | $desired[0].rules[1] | .name = ("Regex" + ($index | tostring)) | .priority = $index]'
check_run 0 1 '讀回驗證完成' --apply

new_case 'Classic 不套用 Standard/Premium Regex 配額' '.sku.name = "Classic_AzureFrontDoor" | .customRules.rules = [range(1;5) as $index | $desired[0].rules[1] | .name = ("Regex" + ($index | tostring)) | .priority = $index]'
check_run 0 1 '讀回驗證完成' --apply

new_case '較早 Allow 阻止套用' '.customRules.rules = [($desired[0].rules[0] | .name = "AllowEarlier" | .priority = 100 | .action = "Allow")]'
check_run 1 0 '較早的 Allow' --apply
case_name='Allow 風險仍可預覽'
check_run 0 0 '套用阻礙: 1' --dry-run

new_case '停用的 Allow 不阻止套用' '.customRules.rules = [($desired[0].rules[0] | .name = "DisabledAllow" | .priority = 100 | .action = "Allow" | .enabledState = "Disabled")]'
check_run 0 1 '讀回驗證完成' --apply

new_case '較後 Allow 不阻止套用' '.customRules.rules = [($desired[0].rules[0] | .name = "LaterAllow" | .priority = 600 | .action = "Allow")]'
check_run 0 1 '讀回驗證完成' --apply

new_case '較早 Block 僅警告' '.customRules.rules = [($desired[0].rules[0] | .name = "EarlierBlock" | .priority = 100)]'
check_run 0 1 '較早的終止規則' --apply

for filter in '.policySettings.mode = "Detection"' '.policySettings.enabledState = "Disabled"' \
    '.securityPolicyLinks = []' '.provisioningState = "Updating"'; do
    new_case "不安全狀態可預覽: $filter" "$filter"
    check_run 0 0 '套用阻礙: 1'
    backup=$(find "$MOCK_DIR/backups/php-policy" -name manifest.json -print)
    jq -e --slurpfile before "$MOCK_DIR/policy.json" '. == $before[0]' "${backup%/*}/original-policy.json" >/dev/null
    case_name="不安全狀態禁止套用: $filter"
    check_run 1 0 '套用前置條件不符' --apply
done

new_case 'Classic frontend 綁定亦可接受' '.securityPolicyLinks = [] | .frontendEndpointLinks = [{id: "/test/frontend"}]'
check_run 0 1 '讀回驗證完成' --apply

new_case '空 customRules 物件' '.customRules = null'
check_run 0 1 '讀回驗證完成' --apply

new_case '不支援的 SKU' '.sku.name = "Unknown"'
check_run 1 0 '不符預期' --apply

new_case '資源 ID 不符' '.id = "/wrong-resource"'
check_run 1 0 '不符預期' --apply

for failure in extension login read; do
    new_case "前置檢查失敗: $failure"
    MOCK_FAILURE=$failure
    check_run 1 0 '錯誤:' --apply
done

new_case 'CLI 版本過舊'
MOCK_VERSION=2.74.0
check_run 1 0 '2.75.0' --apply

new_case '備份失敗零寫入'
printf 'not-a-directory\n' > "$MOCK_DIR/blocked"
check_run 1 0 '備份' --apply --backup-dir "$MOCK_DIR/blocked/subdir"

new_case '更新前漂移零寫入'
MOCK_FAILURE=drift
check_run 1 0 'policy 已變動' --apply

for failure in update timeout verify unrelated; do
    new_case "寫入後失敗不自動回滾: $failure"
    MOCK_FAILURE=$failure
    check_run 1 1 '備份' --apply
    [[ -n $(find "$MOCK_DIR/backups" -name original-policy.json -print) ]]
    jq -e '.controlPlaneVerified == false' "$MOCK_DIR"/backups/php-policy/*/manifest.json >/dev/null
done

for missing in az jq; do
    new_case "缺少相依工具: $missing"
    mkdir "$MOCK_DIR/minimal-bin"
    ln -s "$(command -v dirname)" "$MOCK_DIR/minimal-bin/dirname"
    if [[ "$missing" == az ]]; then
        ln -s "$(command -v jq)" "$MOCK_DIR/minimal-bin/jq"
    else
        ln -s "$temp_dir/bin/az" "$MOCK_DIR/minimal-bin/az"
    fi
    actual_exit=0
    PATH="$MOCK_DIR/minimal-bin" /bin/bash "$root/mitigate-php2shell.sh" "${arguments[@]}" \
        > "$MOCK_DIR/output" 2>&1 || actual_exit=$?
    [[ "$actual_exit" == 1 ]]
    grep -Fq "缺少必要工具: $missing" "$MOCK_DIR/output"
    [[ $(write_count) == 0 ]]
    passed=$((passed + 1))
    printf '通過: %s\n' "$case_name"
done

new_case '衝突的操作旗標'
check_run 1 0 '不可同時使用' --dry-run --apply
new_case '缺少參數值'
check_run 1 0 '缺少值' --policy-name
new_case '未知參數'
check_run 1 0 '未知參數' --unknown

change_policy() {
    jq "$1" "$MOCK_DIR/policy.json" > "$MOCK_DIR/changed.json"
    mv "$MOCK_DIR/changed.json" "$MOCK_DIR/policy.json"
}

prepare_rollback() {
    new_case "$1" "${2:-.}"
    check_run 0 1 '讀回驗證完成' --apply
    rollback_manifest=$(find "$MOCK_DIR/backups" -name manifest.json -print)
    rollback_backup=${rollback_manifest%/*}
}

prepare_rollback '回滾既有 RateLimitRule 並保留目前其他設定' '.customRules.rules = [($desired[0].rules[0] | .name = "ExistingRateLimit" | .priority = 100 | .ruleType = "RateLimitRule" | .action = "Log" | .rateLimitDurationInMinutes = 1 | .rateLimitThreshold = 100 | .groupBy = [])]'
change_policy '.policySettings.mode = "Detection" | .policySettings.enabledState = "Disabled" | .tags.owner = "later-owner" | .securityPolicyLinks = []'
case_name='回滾不受 Disabled、Detection、無綁定影響，保留其他設定'
check_run 0 1 '回滾完成' --rollback "$rollback_backup" --apply
jq -e '.customRules.rules | length == 1 and .[0].name == "ExistingRateLimit" and .[0].rateLimitThreshold == 100' "$MOCK_DIR/policy.json" >/dev/null
jq -e '.policySettings.mode == "Detection" and .policySettings.enabledState == "Disabled" and .tags.owner == "later-owner" and .securityPolicyLinks == []' "$MOCK_DIR/policy.json" >/dev/null
rollback_safety_backup=$(find "$MOCK_DIR/backups" -name manifest.json ! -path "$rollback_manifest" -print)
jq -e '.operation == "rollback" and .controlPlaneVerified == true' "$rollback_safety_backup" >/dev/null
jq -e '.rules | length == 4' "${rollback_safety_backup%/*}/original-custom-rules.json" >/dev/null
case_name='回滾的備份也可復原回回滾前狀態'
check_run 0 1 '回滾完成' --rollback "${rollback_safety_backup%/*}" --apply
jq -e '.customRules.rules | length == 4' "$MOCK_DIR/policy.json" >/dev/null

prepare_rollback '建立後續變更的回滾情境'
change_policy '.customRules.rules += [(.customRules.rules[0] | .name = "LaterRule" | .priority = 900 | .action = "Log")]'
case_name='後續規則變更預設拒絕回滾'
check_run 1 0 '--force-rollback' --rollback "$rollback_backup" --apply
case_name='強制回滾仍預設只預覽'
check_run 0 0 '回滾僅預覽' --rollback "$rollback_backup" --force-rollback
case_name='明確強制回滾才覆寫後續規則'
check_run 0 1 '回滾完成' --rollback "$rollback_backup" --force-rollback --apply
jq -e '.rules == []' "$MOCK_DIR/submitted.json" >/dev/null

new_case '獨立快照備份來源'
check_run 0 0 '備份完成' --backup-only
rollback_manifest=$(find "$MOCK_DIR/backups" -name manifest.json -print)
rollback_backup=${rollback_manifest%/*}
case_name='獨立備份後新增緩解規則'
check_run 0 1 '讀回驗證完成' --apply
case_name='獨立快照後未知變更需確認覆寫'
check_run 1 0 '--force-rollback' --rollback "$rollback_backup" --apply
case_name='從獨立備份完整還原'
check_run 0 1 '回滾完成' --rollback "$rollback_backup" --force-rollback --apply

new_case '逾時的未驗證套用備份'
MOCK_FAILURE=timeout
check_run 1 1 '等待失敗' --apply
rollback_manifest=$(find "$MOCK_DIR/backups" -name manifest.json -print)
rollback_backup=${rollback_manifest%/*}
MOCK_FAILURE=''
change_policy '.provisioningState = "Failed"'
case_name='未驗證備份可在 Failed 狀態回滾'
check_run 0 1 '回滾完成' --rollback "$rollback_backup" --apply
jq -e '.customRules.rules == [] and .provisioningState == "Succeeded"' "$MOCK_DIR/policy.json" >/dev/null

for corruption in target original malformed missing; do
    prepare_rollback "建立備份檢查情境: $corruption"
    case "$corruption" in
        target)
            jq '.resourceId = "/wrong-policy"' "$rollback_manifest" > "$MOCK_DIR/changed.json"
            mv "$MOCK_DIR/changed.json" "$rollback_manifest" ;;
        original)
            jq '.rules = []' "$rollback_backup/original-custom-rules.json" > "$MOCK_DIR/changed.json"
            jq '.rules = [{name:"Corrupted",priority:900}]' "$MOCK_DIR/changed.json" > "$rollback_backup/original-custom-rules.json" ;;
        malformed) printf 'invalid-json\n' > "$rollback_backup/original-custom-rules.json" ;;
        missing) rm "$rollback_backup/manifest.json" ;;
    esac
    case_name="回滾拒絕錯誤備份（force 也無法略過）: $corruption"
    check_run 1 0 '回滾備份' --rollback "$rollback_backup" --force-rollback --apply
done

prepare_rollback '建立尚在更新的 policy'
change_policy '.provisioningState = "Updating"'
case_name='尚在更新時禁止回滾'
check_run 1 0 '尚在更新' --rollback "$rollback_backup" --force-rollback --apply

prepare_rollback '建立回滾前備份失敗情境'
printf 'blocked\n' > "$MOCK_DIR/blocked"
case_name='回滾前備份失敗零寫入'
check_run 1 0 '備份' --rollback "$rollback_backup" --apply --backup-dir "$MOCK_DIR/blocked/subdir"

prepare_rollback '建立回滾前併發漂移情境'
printf '0\n' > "$MOCK_DIR/shows"
MOCK_FAILURE=drift
case_name='強制回滾也不略過寫入前的併發檢查'
check_run 1 0 'policy 已變動' --rollback "$rollback_backup" --force-rollback --apply

for failure in update timeout verify unrelated; do
    prepare_rollback "建立回滾失敗情境: $failure"
    rm "$MOCK_DIR/submitted.json"
    MOCK_FAILURE=$failure
    case_name="回滾失敗保留備份，不連鎖回滾: $failure"
    check_run 1 1 '備份' --rollback "$rollback_backup" --apply
    jq -e '.operation != "rollback" or .controlPlaneVerified == false' "$MOCK_DIR"/backups/php-policy/*/manifest.json >/dev/null
done

new_case '強制回滾旗標不可單獨使用'
check_run 1 0 '僅可搭配' --force-rollback
new_case '備份與回滾互斥'
check_run 1 0 '不可同時使用' --backup-only --rollback /unused
new_case '反向順序仍檢查備份與回滾互斥'
check_run 1 0 '不可同時使用' --rollback /unused --backup-only
new_case '回滾參數缺少路徑'
check_run 1 0 '缺少值' --rollback

for depth in 19 20 21; do
    jq -e --argjson depth "$depth" '
        .rules[1].matchConditions[1].matchValue[0] as $form
        | .rules[2].matchConditions[1].matchValue[0] as $multipart
        | ("field" + ("[part]" * $depth)) as $name
        | [
            (("control=ok&" + $name + "=value") | test($form)),
            (("Content-Disposition: form-data; name=\"" + $name + "\"\r\n") | test($multipart)),
            (("\r\ncontent-disposition: form-data; name=" + $name + "\r\n") | test($multipart)),
            (("CONTENT-DISPOSITION: form-data; name=\"fi\\\"eld" + ("[part]" * $depth) + "\"\r\n") | test($multipart))
          ] | all(.[]; . == ($depth >= 20))
    ' "$root/php2shell-rules.json" >/dev/null
    passed=$((passed + 1))
    printf '通過: %s 層 form/multipart（含引號與跳脫字元）Regex 邊界\n' "$depth"
done
jq -e '
    .rules[1].matchConditions[1].matchValue[0] as $form
    | .rules[2].matchConditions[1].matchValue[0] as $multipart
    | (("normal=value" | test($form)) | not)
      and (("Content-Disposition: form-data; name=\"normal\"\r\n" | test($multipart)) | not)
' "$root/php2shell-rules.json" >/dev/null
passed=$((passed + 1))
printf '通過: 一般表單 Regex 控制組\n'

restore_filter=$(awk '/^[[:space:]]*\. as \$latest$/ {inside=1} /^\047 latest-policy.json/ {inside=0} inside {print}' "$root/README.md")
[[ -n "$restore_filter" ]]
for restore_case in unchanged changed removed unverified wrongid; do
    actual_exit=0
    jq -ne --slurpfile desired "$root/php2shell-rules.json" --arg scenario "$restore_case" '
        $desired[0].rules as $seed
        | [[$seed[0], $seed[2]]] as $added
        | [{customRules: {rules: $seed}}] as $after
        | [{resourceId: "/test", controlPlaneVerified: ($scenario != "unverified")}] as $manifest
        | {id: (if $scenario == "wrongid" then "/other" else "/test" end),
           provisioningState: "Succeeded",
           customRules: {rules: ($seed + [($seed[0] | .name = "Later" | .priority = 900)])}}
        | (if $scenario == "changed" then .customRules.rules[0].action = "Log"
           elif $scenario == "removed" then del(.customRules.rules[0]) else . end)
        | ('"$restore_filter"')
        | [.rules[].name] == ["PhpFormNesting20", "Later"]
    ' > "$MOCK_DIR/restore-output" 2>&1 || actual_exit=$?
    if [[ "$restore_case" == unchanged ]]; then
        [[ "$actual_exit" == 0 ]]
    else
        [[ "$actual_exit" == 5 ]]
    fi
    passed=$((passed + 1))
    printf '通過: 文件還原篩選 %s（保留略過及後續新增規則，漂移時停止）\n' "$restore_case"
done

printf '\n完成 %s 項離線情境，未呼叫真實 Azure CLI。\n' "$passed"