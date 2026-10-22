#!/bin/bash
set -euo pipefail

mock_az() {
    printf '%s\n' "$*" >> "$MOCK_DIR/calls"
    case "${1:-} ${2:-} ${3:-} ${4:-}" in
        'version --output json ')
            jq -n --arg version "${MOCK_VERSION:-2.75.0}" '{"azure-cli": $version}' ;;
        'account show --subscription '*)
            [[ "${MOCK_FAILURE:-}" != login ]] || return 1
            printf '{"id":"11111111-1111-1111-1111-111111111111","state":"Enabled"}\n' ;;
        'network application-gateway waf-policy '*)
            operation=$4
            shift 4
            payload=''
            has_subscription=0; has_group=0; has_policy=0; has_timeout=0
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --subscription) [[ "$2" == 11111111-1111-1111-1111-111111111111 ]]; has_subscription=1; shift 2 ;;
                    --resource-group) [[ "$2" == test-rg ]]; has_group=1; shift 2 ;;
                    --name) [[ "$2" == php-policy ]]; has_policy=1; shift 2 ;;
                    --custom-rules) [[ "$2" == @* ]]; payload=${2#@}; shift 2 ;;
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
                    shows=$(< "$MOCK_DIR/shows"); shows=$((shows + 1))
                    printf '%s\n' "$shows" > "$MOCK_DIR/shows"
                    if [[ "${MOCK_FAILURE:-}" == drift && "$shows" == 2 ]]; then
                        jq '.etag = "concurrent"' "$MOCK_DIR/policy.json"
                    elif [[ "${MOCK_FAILURE:-}" == verify && -f "$MOCK_DIR/submitted.json" ]]; then
                        jq '.customRules += [{name:"Unexpected",priority:99}]' "$MOCK_DIR/policy.json"
                    elif [[ "${MOCK_FAILURE:-}" == unrelated && -f "$MOCK_DIR/submitted.json" ]]; then
                        jq '.tags.owner = "unexpected"' "$MOCK_DIR/policy.json"
                    else jq . "$MOCK_DIR/policy.json"; fi ;;
                update)
                    [[ -n "$payload" ]] || return 92
                    jq -e 'type == "array" and all(.[]; has("state") and (has("enabledState") | not)
                        and all(.matchConditions[]; has("matchVariables") and has("matchValues")
                            and has("negationConditon") and (.operator != "RegEx")))' "$payload" >/dev/null || return 93
                    cp "$payload" "$MOCK_DIR/submitted.json"
                    [[ "${MOCK_FAILURE:-}" != update ]] || return 1
                    jq --slurpfile merged "$payload" '
                        .customRules = $merged[0] | .etag = "after" | .provisioningState = "Succeeded"
                        | .customRules |= map(.matchConditions |= map(
                            .transforms = (.transforms // [])
                            | .matchVariables |= map(.selector = (.selector // null))))
                    ' "$MOCK_DIR/policy.json" > "$MOCK_DIR/next.json"
                    mv "$MOCK_DIR/next.json" "$MOCK_DIR/policy.json" ;;
                wait) [[ "$has_timeout" == 1 && "${MOCK_FAILURE:-}" != timeout ]] ;;
                *) return 94 ;;
            esac ;;
        *) printf '未預期的 Azure 呼叫: %s\n' "$*" >&2; return 95 ;;
    esac
}
if [[ "${0##*/}" == az ]]; then mock_az "$@"; exit; fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/php2shell-appgw-tests.XXXXXX")
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
    MOCK_FAILURE=''; MOCK_VERSION=2.75.0
    printf '0\n' > "$MOCK_DIR/shows"
    : > "$MOCK_DIR/calls"
    jq -n --slurpfile desired "$root/php2shell-rules.json" '
        {id:"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/php-policy",
         name:"php-policy", type:"Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
         location:"eastasia", etag:"before", provisioningState:"Succeeded", tags:{owner:"existing"},
         policySettings:{state:"Enabled",mode:"Prevention",requestBodyCheck:true},
         managedRules:{managedRuleSets:[{ruleSetType:"OWASP",ruleSetVersion:"3.2"}]},
         applicationGateways:[{id:"/test/gateway"}], httpListeners:[], pathBasedRules:[], customRules:[]}
        | '"${2:-.}" > "$MOCK_DIR/policy.json"
}
write_count() { awk '/^network application-gateway waf-policy update / {count++} END {print count+0}' "$MOCK_DIR/calls"; }
check_run() {
    expected_exit=$1; expected_writes=$2; message=$3; shift 3
    before_writes=$(write_count); actual_exit=0
    /bin/bash "$root/mitigate-php2shell.sh" "${arguments[@]}" --backup-dir "$MOCK_DIR/backups" "$@" > "$MOCK_DIR/output" 2>&1 || actual_exit=$?
    after_writes=$(write_count)
    if [[ "$actual_exit" != "$expected_exit" || "$((after_writes - before_writes))" != "$expected_writes" ]] || ! grep -Fq -- "$message" "$MOCK_DIR/output"; then
        printf '失敗: %s (exit=%s, writes=%s)\n' "$case_name" "$actual_exit" "$((after_writes - before_writes))" >&2
        /bin/cat "$MOCK_DIR/output" >&2; exit 1
    fi
    passed=$((passed + 1)); printf '通過: %s\n' "$case_name"
}
change_policy() {
    jq "$1" "$MOCK_DIR/policy.json" > "$MOCK_DIR/next.json"
    mv "$MOCK_DIR/next.json" "$MOCK_DIR/policy.json"
}
prepare_rollback() {
    new_case "$1" "${2:-.}"
    check_run 0 1 '讀回驗證完成' --apply
    rollback_manifest=$(find "$MOCK_DIR/backups" -name manifest.json -print)
    rollback_backup=${rollback_manifest%/*}
}

new_case '預設預覽、持久備份與正確陣列格式'
check_run 0 0 '僅預覽'
backup=$(find "$MOCK_DIR/backups" -name manifest.json -print)
jq -e '.mode == "dry-run" and .controlPlaneVerified == false' "$backup" >/dev/null
jq -e '. == []' "${backup%/*}/original-custom-rules.json" >/dev/null
jq -e 'length == 3' "${backup%/*}/merged-custom-rules.json" >/dev/null
case_name='每次預覽均保存獨立快照'; check_run 0 0 '僅預覽' --dry-run
[[ $(find "$MOCK_DIR/backups" -name manifest.json | awk 'END {print NR}') == 2 ]]
case_name='套用後可直接使用預覽備份回滾'; check_run 0 1 '讀回驗證完成' --apply
case_name='預覽備份回滾'; check_run 0 1 '回滾完成' --rollback "${backup%/*}" --apply

new_case '獨立備份不受衝突與 Detection 影響' '.policySettings.mode = "Detection" | .customRules = [($desired[0][0] | .action = "Allow")]'
check_run 0 0 '備份完成' --backup-only
backup=$(find "$MOCK_DIR/backups" -name manifest.json -print)
jq -e --slurpfile before "$MOCK_DIR/policy.json" '. == $before[0].customRules' "${backup%/*}/original-custom-rules.json" >/dev/null

prepare_rollback '一次寫入三條規則並容忍空 selector'
jq -e '[.[].priority] == [90,91,92]' "$MOCK_DIR/submitted.json" >/dev/null
jq -e '.controlPlaneVerified == true' "$rollback_manifest" >/dev/null
[[ $(stat -f '%Lp' "$rollback_backup" 2>/dev/null || stat -c '%a' "$rollback_backup") == 700 ]]
case_name='相同規則重跑零寫入'; check_run 0 0 '無需更新' --apply
case_name='回滾預覽零寫入'; check_run 0 0 '回滾僅預覽' --rollback "$rollback_backup"
case_name='完整還原空集合'; check_run 0 1 '回滾完成' --rollback "$rollback_backup" --apply
jq -e '.customRules == []' "$MOCK_DIR/policy.json" >/dev/null
case_name='回滾重跑零寫入'; check_run 0 0 '無需回滾' --rollback "$rollback_backup" --apply

new_case '保留既有規則與非目標設定' '.customRules = [($desired[0][0] | .name = "Existing" | .priority = 10 | .action = "Log")]'
check_run 0 1 '讀回驗證完成' --apply
jq -e 'length == 4 and .[0].name == "Existing"' "$MOCK_DIR/submitted.json" >/dev/null
new_case '部分規則存在只新增缺少者' '.customRules = [$desired[0][1]]'
check_run 0 1 '讀回驗證完成' --apply
jq -e 'length == 2' "$MOCK_DIR"/backups/php-policy/*/added-rules.json >/dev/null
for scenario in content case priority duplicates; do
    case "$scenario" in
        content) filter='.customRules = [($desired[0][1] | .action = "Block")]'; message='同名規則內容不同' ;;
        case) filter='.customRules = [($desired[0][0] | .name = "blockphpsessionuploadprogress")]'; message='同名規則內容不同' ;;
        priority) filter='.customRules = [($desired[0][0] | .name = "Other")]'; message='priority 衝突' ;;
        duplicates) filter='.customRules = [($desired[0][0] | .priority = 10), ($desired[0][0] | .priority = 11)]'; message='名稱或 priority 重複' ;;
    esac
    new_case "規則衝突停止: $scenario" "$filter"
    check_run 1 0 "$message" --dry-run
    [[ -n $(find "$MOCK_DIR/backups" -name original-policy.json -print) ]]
done
new_case '100 條規則邊界' '.customRules = [range(1;101) | select(. < 90 or . > 92) | . as $priority | $desired[0][0] | .priority = $priority | .name = ("Existing" + ($priority | tostring)) | .action = "Log"]'
check_run 0 1 '讀回驗證完成' --apply
new_case '規則數量超限' '.customRules = [range(1;102) | select(. < 90 or . > 92) | . as $priority | $desired[0][0] | .priority = $priority | .name = ("Existing" + ($priority | tostring)) | .action = "Log"]'
check_run 1 0 '配額' --apply
new_case '無 Front Door 的五條 Regex 限制' '.customRules = [range(1;7) as $priority | $desired[0][1] | .priority = $priority | .name = ("Regex" + ($priority | tostring))]'
check_run 0 1 '讀回驗證完成' --apply
new_case '條件數超限' '.customRules = [($desired[0][0] | .name = "Existing" | .priority = 10 | .action = "Log" | .matchConditions = [range(0;11) | $desired[0][0].matchConditions[0]])]'
check_run 1 0 '配額' --apply
new_case '較早 Allow 停止套用' '.customRules = [($desired[0][0] | .name = "AllowEarlier" | .priority = 10 | .action = "Allow")]'
check_run 1 0 '較早的 Allow' --apply
case_name='Allow 風險可預覽'; check_run 0 0 '套用阻礙: 1'
new_case '停用 Allow 不阻止套用' '.customRules = [($desired[0][0] | .name = "DisabledAllow" | .priority = 10 | .action = "Allow" | .state = "Disabled")]'
check_run 0 1 '讀回驗證完成' --apply
new_case '較後 Allow 不阻止套用' '.customRules = [($desired[0][0] | .name = "LaterAllow" | .priority = 99 | .action = "Allow")]'
check_run 0 1 '讀回驗證完成' --apply
for filter in '.policySettings.mode = "Detection"' '.policySettings.state = "Disabled"' '.applicationGateways = []' '.provisioningState = "Updating"'; do
    new_case "不安全狀態可預覽: $filter" "$filter"; check_run 0 0 '套用阻礙: 1'
    case_name="不安全狀態不可寫入: $filter"; check_run 1 0 '套用前置條件不符' --apply
done
new_case '所有阻礙一次列出' '.policySettings.mode = "Detection" | .policySettings.state = "Disabled" | .provisioningState = "Failed" | .applicationGateways = [] | .customRules = [($desired[0][0] | .name = "AllowEarlier" | .priority = 10 | .action = "Allow")]'
check_run 1 0 '套用前置條件不符（5 項）' --apply
new_case '缺少欄位顯示 null' 'del(.policySettings.mode, .provisioningState)'
check_run 1 0 'policySettings.mode 目前為 null' --apply
for binding in httpListeners pathBasedRules; do
    new_case "接受 $binding 綁定" ".applicationGateways = [] | .$binding = [{id:\"/test/binding\"}]"
    check_run 0 1 '讀回驗證完成' --apply
done
new_case 'null customRules' '.customRules = null'; check_run 0 1 '讀回驗證完成' --apply
new_case '資源 ID 錯誤' '.id = "/wrong"'; check_run 1 0 '不符預期' --apply
new_case '不接受 Front Door 規則容器' '.customRules = {rules:[]}'
check_run 1 0 '不符預期' --apply
for failure in login read; do
    new_case "前置檢查失敗: $failure"; MOCK_FAILURE=$failure; check_run 1 0 '錯誤:' --apply
done
new_case 'CLI 版本過舊'; MOCK_VERSION=2.74.0; check_run 1 0 '2.75.0' --apply
new_case '備份失敗零寫入'; printf 'blocked\n' > "$MOCK_DIR/blocked"
check_run 1 0 '備份' --apply --backup-dir "$MOCK_DIR/blocked/subdir"
new_case '更新前漂移零寫入'; MOCK_FAILURE=drift; check_run 1 0 'policy 已變動' --apply
for failure in update timeout verify unrelated; do
    new_case "寫入後失敗不自動回滾: $failure"; MOCK_FAILURE=$failure
    check_run 1 1 '備份' --apply
    jq -e '.controlPlaneVerified == false' "$MOCK_DIR"/backups/php-policy/*/manifest.json >/dev/null
done
prepare_rollback '回滾保留既有 RateLimitRule' '.customRules = [($desired[0][0] | .name = "ExistingRate" | .priority = 10 | .ruleType = "RateLimitRule" | .action = "Log" | .rateLimitDuration = "OneMin" | .rateLimitThreshold = 100 | .groupByUserSession = [{groupByVariables:[{variableName:"ClientAddr"}]}])]'
change_policy '.policySettings.mode = "Detection" | .policySettings.state = "Disabled" | .tags.owner = "later" | .applicationGateways = []'
case_name='回滾不改動模式、綁定或 tags'; check_run 0 1 '回滾完成' --rollback "$rollback_backup" --apply
jq -e '.customRules | length == 1 and .[0].rateLimitThreshold == 100' "$MOCK_DIR/policy.json" >/dev/null
jq -e '.policySettings.state == "Disabled" and .tags.owner == "later"' "$MOCK_DIR/policy.json" >/dev/null
prepare_rollback '建立後續變更回滾情境'
change_policy '.customRules += [(.customRules[0] | .name = "Later" | .priority = 99 | .action = "Log")]'
case_name='後續變更拒絕回滾'; check_run 1 0 '--force-rollback' --rollback "$rollback_backup" --apply
case_name='強制回滾預設僅預覽'; check_run 0 0 '回滾僅預覽' --rollback "$rollback_backup" --force-rollback
case_name='明確強制回滾覆寫後續變更'; check_run 0 1 '回滾完成' --rollback "$rollback_backup" --force-rollback --apply
for corruption in target original malformed missing; do
    prepare_rollback "建立損壞備份情境: $corruption"
    case "$corruption" in
        target) jq '.resourceId = "/wrong"' "$rollback_manifest" > "$MOCK_DIR/next.json"; mv "$MOCK_DIR/next.json" "$rollback_manifest" ;;
        original) printf '[{"name":"Corrupted","priority":99}]\n' > "$rollback_backup/original-custom-rules.json" ;;
        malformed) printf 'invalid-json\n' > "$rollback_backup/original-custom-rules.json" ;;
        missing) rm "$rollback_backup/manifest.json" ;;
    esac
    case_name="force 亦拒絕錯誤備份: $corruption"; check_run 1 0 '回滾備份' --rollback "$rollback_backup" --force-rollback --apply
done
prepare_rollback '建立尚在更新回滾情境'; change_policy '.provisioningState = "Updating"'
case_name='Updating 拒絕回滾'; check_run 1 0 '尚在更新' --rollback "$rollback_backup" --force-rollback --apply
for failure in drift update timeout verify unrelated; do
    prepare_rollback "建立回滾失敗情境: $failure"
    rm "$MOCK_DIR/submitted.json"; printf '0\n' > "$MOCK_DIR/shows"; MOCK_FAILURE=$failure
    expected_writes=1; message='備份'
    if [[ "$failure" == drift ]]; then expected_writes=0; message='policy 已變動'; fi
    case_name="回滾失敗不連鎖重試: $failure"
    check_run 1 "$expected_writes" "$message" --rollback "$rollback_backup" --apply
done
new_case 'force 單獨使用仍僅預覽' '.policySettings.mode = "Detection"'
check_run 0 0 '僅預覽' --force
grep -Fq -- '--force：略過 1 項' "$MOCK_DIR/output"
backup=$(find "$MOCK_DIR/backups" -name manifest.json -print)
jq -e '.force == true and .mode == "dry-run" and .controlPlaneVerified == false' "$backup" >/dev/null
case_name='force 明確 dry-run 仍零寫入'; check_run 0 0 '僅預覽' --force --dry-run
for filter in '.policySettings.mode = "Detection"' '.policySettings.state = "Disabled"' '.applicationGateways = []' '.provisioningState = "Updating"' '.customRules = [($desired[0][0] | .name = "AllowEarlier" | .priority = 10 | .action = "Allow")]'; do
    new_case "force 略過單項前置警告: $filter" "$filter"
    check_run 0 1 '--force：略過 1 項' --force --apply
    jq -e '.controlPlaneVerified == true and .force == true' "$MOCK_DIR"/backups/php-policy/*/manifest.json >/dev/null
done
new_case 'force 同時略過五項警告' '.policySettings.mode = "Detection" | .policySettings.state = "Disabled" | .provisioningState = "Failed" | .applicationGateways = [] | .customRules = [($desired[0][0] | .name = "AllowEarlier" | .priority = 10 | .action = "Allow")]'
check_run 0 1 '--force：略過 5 項' --apply --force
for reason in 'policySettings.mode' 'policySettings.state' 'provisioningState' '未發現 policy 綁定' '較早的 Allow'; do
    grep -Fq "$reason" "$MOCK_DIR/output"
done
jq -e '.policySettings.mode == "Detection" and .policySettings.state == "Disabled" and .applicationGateways == [] and .customRules[0].action == "Allow"' "$MOCK_DIR/policy.json" >/dev/null
case_name='force 不破壞零寫入重跑'; check_run 0 0 '無需更新' --force --apply
new_case '無警告也可 force 套用'; check_run 0 1 '讀回驗證完成' --force --apply
new_case 'force 不略過同名衝突' '.customRules = [($desired[0][0] | .action = "Log")]'
check_run 1 0 '同名規則內容不同' --force --apply
new_case 'force 不略過 priority 衝突' '.customRules = [($desired[0][0] | .name = "Other")]'
check_run 1 0 'priority 衝突' --force --apply
new_case 'force 不略過配額' '.customRules = [($desired[0][0] | .name = "Other" | .priority = 101)]'
check_run 1 0 '配額' --force --apply
new_case 'force 不略過目標驗證' '.id = "/wrong"'; check_run 1 0 '不符預期' --force --apply
new_case 'force 不略過備份失敗'; printf 'blocked\n' > "$MOCK_DIR/blocked"
check_run 1 0 '備份' --force --apply --backup-dir "$MOCK_DIR/blocked/subdir"
new_case 'force 不略過漂移'; MOCK_FAILURE=drift; check_run 1 0 'policy 已變動' --force --apply
for failure in update timeout verify unrelated; do
    new_case "force 不略過寫入後失敗: $failure"; MOCK_FAILURE=$failure
    check_run 1 1 '備份' --force --apply
    jq -e '.force == true and .controlPlaneVerified == false' "$MOCK_DIR"/backups/php-policy/*/manifest.json >/dev/null
done
new_case 'force 不可搭配備份'; check_run 1 0 '--force 僅可用於' --force --backup-only
new_case 'force 不可替代 force-rollback'; check_run 1 0 '--force 僅可用於' --rollback /unused --force --apply
new_case '反向順序亦拒絕 force 與回滾'; check_run 1 0 '--force 僅可用於' --force --rollback /unused
new_case '互斥模式'; check_run 1 0 '不可同時使用' --dry-run --apply
new_case '備份與 apply 互斥'; check_run 1 0 '不可與' --backup-only --apply
new_case '備份與回滾互斥'; check_run 1 0 '不可同時使用' --rollback /unused --backup-only
new_case 'force 不能單獨使用'; check_run 1 0 '僅可搭配' --force-rollback
new_case '參數缺少值'; check_run 1 0 '缺少值' --policy-name
new_case '未知參數'; check_run 1 0 '未知參數' --unknown
new_case '拒絕路徑穿越'; check_run 1 0 'policy-name' --policy-name ../other
for missing in az jq; do
    new_case "缺少相依工具: $missing"; mkdir "$MOCK_DIR/minimal-bin"
    ln -s "$(command -v dirname)" "$MOCK_DIR/minimal-bin/dirname"
    if [[ "$missing" == az ]]; then ln -s "$(command -v jq)" "$MOCK_DIR/minimal-bin/jq"
    else ln -s "$temp_dir/bin/az" "$MOCK_DIR/minimal-bin/az"; fi
    actual_exit=0
    PATH="$MOCK_DIR/minimal-bin" /bin/bash "$root/mitigate-php2shell.sh" "${arguments[@]}" > "$MOCK_DIR/output" 2>&1 || actual_exit=$?
    [[ "$actual_exit" == 1 ]]; grep -Fq "缺少必要工具: $missing" "$MOCK_DIR/output"
    [[ $(write_count) == 0 ]]; passed=$((passed + 1)); printf '通過: %s\n' "$case_name"
done
for depth in 19 20 21; do
    jq -e --argjson depth "$depth" '
        .[1].matchConditions[1].matchValues[0] as $form
        | .[2].matchConditions[1].matchValues[0] as $multipart
        | ("field" + ("[part]" * $depth)) as $name
        | [(("control=ok&" + $name + "=value") | test($form)), ($name | test($multipart))]
        | all(.[]; . == ($depth >= 20))
    ' "$root/php2shell-rules.json" >/dev/null
    passed=$((passed + 1)); printf '通過: %s 層 form 與 PostArgs Regex 邊界\n' "$depth"
done
jq -e '.[1].matchConditions[1].matchValues[0] as $form | .[2].matchConditions[1].matchValues[0] as $multipart
    | (("normal=value" | test($form)) | not) and (("normal" | test($multipart)) | not)' "$root/php2shell-rules.json" >/dev/null
passed=$((passed + 1))
printf '\n完成 %s 項離線情境，未呼叫真實 Azure CLI。\n' "$passed"