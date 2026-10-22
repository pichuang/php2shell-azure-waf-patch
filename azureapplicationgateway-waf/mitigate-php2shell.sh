#!/bin/bash
set -euo pipefail
umask 077

usage() {
    printf '%s\n' \
        '用法: mitigate-php2shell.sh --subscription NAME_OR_ID --resource-group RG --policy-name POLICY [--dry-run | --apply] [--force] [--backup-dir DIR]' \
        '獨立備份: --backup-only；回滾預覽: --rollback BACKUP_DIR，加 --apply 才寫入。' \
        '--force 略過套用前置警告（狀態、綁定、較早 Allow），仍需 --apply 才寫入；不略過備份、衝突或漂移保護。' \
        '回滾遇到其他 custom rules 變更時停止；--force-rollback 明確允許覆寫。' \
        '預設僅預覽並備份；--apply 才修改既有 PHP 專用 Application Gateway WAF policy。' \
        'priority 固定為 90/91/92，動作為 Block/Log/Log。不修改綁定或全域設定。' \
        '備份位置: backups/POLICY_NAME/每次執行目錄；--backup-dir 可更改根目錄。' \
        '套用前請確認此 policy 僅涵蓋受影響的 PHP 網域及路徑，且沒有其他寫入者。'
}
die() { printf '錯誤: %s\n' "$*" >&2; exit 1; }
warn() { printf '警告: %s\n' "$*" >&2; }

subscription=''
resource_group=''
policy_name=''
mode='dry-run'
mode_selected=''
operation='mitigate'
rollback_source=''
force_rollback=0
force=0
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
backup_root="$script_dir/backups"
backup_path=''
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --subscription|--resource-group|--policy-name|--backup-dir|--rollback)
            [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || die "$1 缺少值"
            case "$1" in
                --subscription) subscription=$2 ;;
                --resource-group) resource_group=$2 ;;
                --policy-name) policy_name=$2 ;;
                --backup-dir) backup_root=$2 ;;
                --rollback) rollback_source=$2 ;;
            esac
            shift 2 ;;
        --dry-run|--apply)
            [[ -z "$mode_selected" || "$mode_selected" == "$1" ]] || die '--dry-run 與 --apply 不可同時使用'
            mode_selected=$1; mode=${1#--}; shift ;;
        --backup-only) operation='backup'; shift ;;
        --force) force=1; shift ;;
        --force-rollback) force_rollback=1; shift ;;
        *) die "未知參數: $1" ;;
    esac
done
if [[ -n "$rollback_source" ]]; then
    [[ "$operation" != backup ]] || die '--backup-only 與 --rollback 不可同時使用'
    operation='rollback'
fi
[[ "$force_rollback" == 0 || "$operation" == rollback ]] || die '--force-rollback 僅可搭配 --rollback'
[[ "$force" == 0 || "$operation" == mitigate ]] || die '--force 僅可用於新增緩解規則，不可搭配 --backup-only 或 --rollback；回滾請使用 --force-rollback'
[[ "$operation" != backup || -z "$mode_selected" ]] || die '--backup-only 不可與 --dry-run 或 --apply 同時使用'
[[ -n "$subscription" && -n "$resource_group" && -n "$policy_name" ]] || { usage >&2; die '請提供三個目標參數'; }
[[ "$policy_name" != */* && "$policy_name" != *\\* && "$policy_name" != . && "$policy_name" != .. ]] || die 'policy-name 不可包含路徑分隔符或為 .、..'
for dependency in az jq; do
    command -v "$dependency" >/dev/null 2>&1 || die "缺少必要工具: $dependency"
done
export AZURE_EXTENSION_USE_DYNAMIC_INSTALL=no
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/php2shell-appgw.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'printf "執行失敗；備份位置: %s\n" "${backup_path:-尚未建立}" >&2' ERR
az version --output json > "$work_dir/version.json" || die '無法讀取 Azure CLI 版本'
jq -e '.["azure-cli"] | split(".") | map(tonumber) | .[0] > 2 or (.[0] == 2 and .[1] >= 75)' "$work_dir/version.json" >/dev/null || die '需要 Azure CLI 2.75.0 或更新版本'
jq -ne 'walk(.) == null' >/dev/null || die '需要 jq 1.6 或更新版本'
az account show --subscription "$subscription" --output json > "$work_dir/account.json" || die '無法存取訂用帳戶；請先 az login 並確認權限'
jq -e '.state == "Enabled" and (.id | type == "string" and length > 0)' "$work_dir/account.json" >/dev/null || die '訂用帳戶不是 Enabled 或回應缺少 ID'
subscription=$(jq -r '.id' "$work_dir/account.json")
target=(--subscription "$subscription" --resource-group "$resource_group" --name "$policy_name" --only-show-errors)
get_policy() {
    az network application-gateway waf-policy show "${target[@]}" --output json > "$1" || die '無法讀取 WAF policy；請確認目標、登入與讀取權限'
}
save_backup_plan() {
    cp "$work_dir/merged.json" "$backup_path/merged-custom-rules.json"
    jq '.added' "$work_dir/plan.json" > "$backup_path/added-rules.json"
}
persist_backup() {
    local policy_backup_root="$backup_root/$policy_name"
    mkdir -p -- "$policy_backup_root" || die '無法建立 policy 備份目錄'
    backup_path=$(mktemp -d "$policy_backup_root/php2shell-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX") || die '無法建立備份目錄'
    cp "$work_dir/before.json" "$backup_path/original-policy.json"
    jq '.customRules // []' "$work_dir/before.json" > "$backup_path/original-custom-rules.json"
    save_backup_plan
    jq -n --arg id "$(jq -r '.id' "$work_dir/before.json")" --arg time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg operation "$operation" --arg source "$rollback_source" --arg mode "$mode" --argjson force "$force" \
        '{resourceId: $id, createdAt: $time, operation: $operation, mode: $mode, force: ($force == 1), rollbackSource: $source, controlPlaneVerified: false}' > "$backup_path/manifest.json"
    printf '備份: %s\n' "$backup_path"
}
normalizers='
def clean: walk(if type == "object" then with_entries(select(.value != null)) else . end);
def rule:
    .state = (.state // "Enabled")
    | .matchConditions |= (map(
        .negationConditon = (.negationConditon // false)
        | .transforms = (.transforms // [])
        | .matchValues |= sort
        | .matchVariables |= (map(if .selector == "" then del(.selector) else . end) | sort_by(.variableName, .selector))
            ) | clean | sort_by(.matchVariables, .operator, .matchValues)) | clean;
def custom: (. // []) | map(rule) | sort_by(.name) | clean;
def stable: del(.customRules, .etag, .provisioningState, .resourceState, .systemData) | clean;
'
apply_custom_rules() {
    persist_backup
    get_policy "$work_dir/recheck.json"
    jq -e --slurpfile before "$work_dir/before.json" '. == $before[0]' "$work_dir/recheck.json" >/dev/null || die '備份後 policy 已變動；請重新預覽，不會覆寫其他變更'
    if ! az network application-gateway waf-policy update "${target[@]}" \
        --custom-rules "@$work_dir/merged.json" --output none; then
        die "更新失敗或結果不確定；不自動回滾。請檢查 Azure 與備份: $backup_path"
    fi
    if ! az network application-gateway waf-policy wait "${target[@]}" --updated --interval 10 --timeout 600; then
        die "等待失敗或逾時；更新可能仍在進行。請檢查 Azure 與備份: $backup_path"
    fi
    get_policy "$backup_path/verified-after.json"
    jq -e --slurpfile before "$work_dir/before.json" --slurpfile merged "$work_dir/merged.json" "$normalizers"'
        .provisioningState == "Succeeded"
        and ((.customRules | custom) == ($merged[0] | custom))
        and ((. | stable) == ($before[0] | stable))
    ' "$backup_path/verified-after.json" >/dev/null || die "讀回驗證不符；不自動回滾。請檢查備份: $backup_path"
    jq '.controlPlaneVerified = true' "$backup_path/manifest.json" > "$work_dir/verified-manifest.json"
    mv "$work_dir/verified-manifest.json" "$backup_path/manifest.json"
}

get_policy "$work_dir/before.json"
expected_id="/subscriptions/$subscription/resourceGroups/$resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/$policy_name"
jq -e --arg id "$expected_id" '
    (.id | ascii_downcase) == ($id | ascii_downcase)
    and ((.customRules // []) | type == "array") and (.policySettings | type == "object")
' "$work_dir/before.json" >/dev/null || die 'policy ID 或回應結構不符預期'
printf '目標: %s\n' "$(jq -r '.id' "$work_dir/before.json")"
jq '{location, provisioningState, policySettings, applicationGateways, httpListeners, pathBasedRules}' "$work_dir/before.json"
if [[ "$operation" == backup || "$mode" == dry-run ]]; then
    jq '.customRules // []' "$work_dir/before.json" > "$work_dir/merged.json"
    printf '{"added":[]}\n' > "$work_dir/plan.json"
    persist_backup
    if [[ "$operation" == backup ]]; then
        printf '既有 custom rules 備份完成，未寫入 Azure。\n'; exit 0
    fi
fi
if [[ "$operation" == rollback ]]; then
    for filename in manifest.json original-policy.json original-custom-rules.json merged-custom-rules.json; do
        [[ -f "$rollback_source/$filename" ]] || die "回滾備份缺少檔案: $filename"
        cp -- "$rollback_source/$filename" "$work_dir/rollback-$filename" || die "無法讀取回滾備份: $filename"
    done
    jq -e --slurpfile manifest "$work_dir/rollback-manifest.json" --slurpfile original "$work_dir/rollback-original-policy.json" \
        --slurpfile before "$work_dir/before.json" "$normalizers"'
        ($manifest | length == 1) and ($original | length == 1) and (type == "array")
        and (($manifest[0].resourceId | ascii_downcase) == ($before[0].id | ascii_downcase))
        and (($original[0].id | ascii_downcase) == ($before[0].id | ascii_downcase))
        and ((. | custom) == ($original[0].customRules | custom))
        and all(.[]; (.name | type == "string" and length > 0)
            and (.priority | type == "number" and . >= 1 and . <= 100 and floor == .)
            and (.ruleType | IN("MatchRule", "RateLimitRule"))
            and (.action | type == "string" and length > 0) and (.matchConditions | type == "array"))
        and (group_by(.name | ascii_downcase) | all(.[]; length == 1))
        and (group_by(.priority) | all(.[]; length == 1))
    ' "$work_dir/rollback-original-custom-rules.json" >/dev/null || die '回滾備份損壞、內容不一致或目標 policy 不符'
    jq -e 'type == "array"' "$work_dir/rollback-merged-custom-rules.json" >/dev/null || die '回滾備份的預期規則格式不符'
    cp "$work_dir/rollback-original-custom-rules.json" "$work_dir/merged.json"
    printf '{"added":[]}\n' > "$work_dir/plan.json"
    if [[ "$mode" == dry-run ]]; then save_backup_plan; fi
    printf '回滾來源: %s\n回滾將還原以下完整 custom rules（其餘設定維持目前值）:\n' "$rollback_source"
    jq . "$work_dir/merged.json"
    if [[ "$mode" == apply ]]; then
        jq -e '.provisioningState | IN("Succeeded", "Failed")' "$work_dir/before.json" >/dev/null || die 'policy 尚在更新或狀態未知，請等待完成後再回滾'
    fi
    if jq -e --slurpfile original "$work_dir/merged.json" "$normalizers"'(.customRules | custom) == ($original[0] | custom)' "$work_dir/before.json" >/dev/null; then
        printf '目前 custom rules 已與備份相同，無需回滾。\n'; exit 0
    fi
    if ! jq -e --slurpfile expected "$work_dir/rollback-merged-custom-rules.json" "$normalizers"'(.customRules | custom) == ($expected[0] | custom)' "$work_dir/before.json" >/dev/null; then
        [[ "$force_rollback" == 1 ]] || die 'custom rules 已有其他變更；確認要捨棄這些變更後，才加 --force-rollback'
        warn '--force-rollback：將覆寫備份之後的 custom rules 變更'
    fi
    if [[ "$mode" == dry-run ]]; then printf '回滾僅預覽，未寫入 Azure；加 --apply 才執行。\n'; exit 0; fi
    apply_custom_rules
    printf '回滾完成，完整 custom rules 已還原並通過讀回驗證；其餘 policy 設定未變更。\n'
    exit 0
fi
desired="$script_dir/php2shell-rules.json"
jq -e '
    type == "array" and length == 3
    and ([.[].name] == ["BlockPhpSessionUploadProgress", "PhpFormNesting20", "PhpMultipartNesting20"])
    and ([.[].priority] == [90,91,92]) and ([.[].action] == ["Block","Log","Log"])
    and all(.[]; .state == "Enabled" and .ruleType == "MatchRule" and (.matchConditions | length == 2)
        and all(.matchConditions[]; (.matchVariables | length > 0) and (.matchValues | length > 0)
            and all(.matchValues[]; length <= 256)))
' "$desired" >/dev/null || die '規則來源遺失或格式不符預期'
jq -e --slurpfile desired "$desired" "$normalizers"'
    (.customRules // []) as $existing
    | if ($existing | group_by(.name | ascii_downcase) | any(.[]; length > 1))
        or ($existing | group_by(.priority) | any(.[]; length > 1))
      then error("既有規則名稱或 priority 重複") else . end
    | reduce $desired[0][] as $wanted
        ({merged: $existing, added: [], skipped: []};
         ([.merged[] | select((.name | ascii_downcase) == ($wanted.name | ascii_downcase))]) as $same
         | if ($same | length) > 0 then
             if ($same[0] | rule) == ($wanted | rule) then .skipped += [$wanted.name]
             else error("同名規則內容不同，拒絕覆寫: " + $wanted.name) end
           elif any(.merged[]; .priority == $wanted.priority) then error("priority 衝突: " + ($wanted.priority | tostring))
           else .merged += [$wanted] | .added += [$wanted] end)
' "$work_dir/before.json" > "$work_dir/plan.json" || die '規則合併檢查失敗，未寫入 Azure'
jq -e '
    (.merged | length <= 100)
    and all(.merged[]; (.priority | type == "number" and . >= 1 and . <= 100 and floor == .)
        and (.matchConditions | length <= 10))
' "$work_dir/plan.json" >/dev/null || die '合併結果超過 custom rules、priority 或條件數量配額'
jq '.merged' "$work_dir/plan.json" > "$work_dir/merged.json"
if [[ "$mode" == dry-run ]]; then save_backup_plan; fi
jq '{"新增": [.added[] | {name, priority, action}], "略過": .skipped}' "$work_dir/plan.json"
printf '預期完整 custom rules:\n'
jq . "$work_dir/merged.json"
jq --slurpfile desired "$desired" '
    [.customRules[]? | select((.state // "Enabled") == "Enabled" and .priority < 92 and .action != "Log")
     | select(.name as $name | all($desired[0][]; .name != $name))]
' "$work_dir/before.json" > "$work_dir/earlier.json"
if jq -e 'length > 0' "$work_dir/earlier.json" >/dev/null; then
    warn '較早的終止規則可能先處理請求；請審查下列完整條件'; jq . "$work_dir/earlier.json" >&2
fi
block_reasons=()
for field in state mode; do
    expected='Enabled'
    if [[ "$field" == mode ]]; then expected='Prevention'; fi
    if ! jq -e --arg field "$field" --arg expected "$expected" '.policySettings[$field] == $expected' "$work_dir/before.json" >/dev/null; then
        block_reasons+=("policySettings.$field 目前為 $(jq -r --arg field "$field" '.policySettings[$field] | tojson' "$work_dir/before.json")，要求為 ${expected}。請先評估流量與誤判影響，再由操作人員調整；腳本不會自動調整。")
    fi
done
if ! jq -e '.provisioningState == "Succeeded"' "$work_dir/before.json" >/dev/null; then
    block_reasons+=("provisioningState 目前為 $(jq -r '.provisioningState | tojson' "$work_dir/before.json")，要求為 Succeeded。Updating 請等待完成；Failed 或未知狀態請先排查。")
fi
if ! jq -e '((.applicationGateways // []) + (.httpListeners // []) + (.pathBasedRules // [])) | length > 0' "$work_dir/before.json" >/dev/null; then
    block_reasons+=('未發現 policy 綁定：applicationGateways、httpListeners 與 pathBasedRules 合計為 0，要求至少 1 個綁定參照。請核對 gateway、listener 或 path 綁定；腳本不會修改綁定。')
fi
if jq -e 'any(.[]; .action == "Allow")' "$work_dir/earlier.json" >/dev/null; then
    block_reasons+=("較早的 Allow 可略過後續緩解規則：$(jq -r '[.[] | select(.action == "Allow") | "\(.name) (priority=\(.priority))"] | join(", ")' "$work_dir/earlier.json")。請人工審查條件及優先順序；腳本不會修改既有規則。")
fi
blockers=${#block_reasons[@]}
if [[ "$force" == 1 && "$blockers" != 0 ]]; then
    warn "--force：略過 ${blockers} 項套用前置警告；不會調整模式、啟用狀態、綁定或既有 Allow，規則可能無法實際保護流量。"
    printf '  - %s\n' "${block_reasons[@]}" >&2
fi
if [[ "$mode" == dry-run ]]; then
    printf '僅預覽，未寫入 Azure。套用阻礙: %s\n' "$blockers"
    if [[ "$blockers" != 0 ]]; then printf '  - %s\n' "${block_reasons[@]}" >&2; fi
    exit 0
fi
if [[ "$blockers" != 0 && "$force" == 0 ]]; then
    die "$(printf '套用前置條件不符（%s 項），未寫入 Azure。原因與處理方向：\n' "$blockers"; printf '  - %s\n' "${block_reasons[@]}")"
fi
if jq -e '.added | length == 0' "$work_dir/plan.json" >/dev/null; then printf '三條規則均相同，無需更新。\n'; exit 0; fi
apply_custom_rules
printf '控制平面更新與讀回驗證完成。尚須驗證實際流量與 WAF 記錄；Log 規則不阻擋請求。\n'