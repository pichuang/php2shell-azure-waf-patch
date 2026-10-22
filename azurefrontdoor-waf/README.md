# azurefrontdoor-waf

透過 Azure CLI 將 Microsoft 建議的三條 PHP2Shell 緩解規則加入**既有 PHP 專用 Azure Front Door WAF policy**。每次只處理一個 policy，priority 固定從 500 開始，不建立 policy、不修改網域、路由或 security policy 綁定。

這是暫時緩解措施，不是 PHP 漏洞修補；完整修復仍須升級至已修補的 PHP 版本。依據 [Microsoft 原文（2026-10-21，版本 2.0）](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684)。

## 規則

定義集中於 [php2shell-rules.json](php2shell-rules.json)，保留原文的條件、轉換與正規表示式，只調整 priority。

| Priority | 名稱 | 動作 | 比對內容 |
| --- | --- | --- | --- |
| 500 | BlockPhpSessionUploadProgress | Block | multipart 本文包含 `php_session_upload_progress`，不分大小寫 |
| 501 | PhpFormNesting20 | Log | URL 解碼後的 form 欄位名稱含至少 20 層方括號參數 |
| 502 | PhpMultipartNesting20 | Log | multipart 欄位名稱含至少 20 層方括號參數 |

各條規則的兩個條件為 AND。`Log` 只記錄、不阻擋，且繼續評估後續規則。20 層是應用政策門檻，不是漏洞的保證邊界。確認合法流量相容性後，才另行考慮將兩條 Log 規則改為 Block；本工具不自動升級動作。

## 前置需求

- Bash 3.2 以上，適用 macOS、Linux 與 Azure Cloud Shell 的 Bash 環境。
- [Azure CLI 2.75.0 以上](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy?view=azure-cli-latest)、`front-door` extension、jq 1.6 以上。
- Azure 登入與目標 policy 的讀取、寫入權限，例如適當資源範圍的 Network Contributor，不需要 Owner。預覽只需讀取權限；寫入權限與 Azure Policy 是否允許變更，最終由 Azure 更新要求判定。
- 既有且已綁定的 Front Door WAF policy；套用要求 `Enabled`、`Prevention`、`provisioningState: Succeeded`。
- 人工確認 policy 僅涵蓋受影響的 PHP 網域及路由，包含沒有 `.php` 副檔名的 PHP 路由。綁定參照存在不代表此範圍已正確。

先由操作人員完成安裝與登入；腳本不會自動安裝、登入或切換全域訂用帳戶：

```bash
az login
az extension add --name front-door
az extension update --name front-door
az version
jq --version
chmod +x mitigate-php2shell.sh tests/test-mitigate-php2shell.sh
```

## 操作

先預覽，替換三個目標參數：

```bash
./mitigate-php2shell.sh \
	--subscription '<subscription-name-or-id>' \
	--resource-group '<resource-group>' \
	--policy-name '<existing-php-waf-policy>'
```

預設為 `--dry-run`，會讀取 Azure 並顯示目標 ID、設定、綁定參照、新增、略過清單與完整合併後規則，不寫入 Azure，也不建立持久備份。Disabled、Detection 或無綁定等狀態仍可預覽，但會顯示套用阻礙；規則衝突或配額超限則以非零狀態停止。

核對目標、誤判風險與變更內容後，才明確套用：

```bash
./mitigate-php2shell.sh \
	--subscription '<subscription-name-or-id>' \
	--resource-group '<resource-group>' \
	--policy-name '<existing-php-waf-policy>' \
	--apply
```

可用 `--backup-dir '/secure/path'` 改變備份根目錄；預設位於腳本旁的 `backups/`。備份可能含敏感的既有規則與設定，請妥善管理；自訂備份路徑不會自動加入 Git 忽略清單。`--help` 不需要 Azure 登入。

### 更新保護

- 保留所有非目標 custom rules、managed rules、tags、SKU 與其餘 policy settings；不修改 `requestBodyCheck`。
- 同名同內容略過，容忍 Azure 回傳的空值與已知預設欄位；三條都相同時零寫入。
- 同名不同內容立即停止，包含已由操作人員將 Log 提升為 Block 的情況，不會降回 Log。名稱大小寫碰撞亦停止。
- priority 500、501、502 被其他規則占用即停止，不自動換號或重排。
- 檢查名稱、priority 重複、100 條 custom rules、每條 10 個條件；Standard／Premium 另檢查最多 5 條含 Regex 的 custom rules，本次新增最多占 2 條。Classic 不套用此 5 條限制，仍須遵守服務實際配額。
- 較早且已啟用的 Allow 可能略過後續規則，因此阻止套用；較早的其他終止動作列出條件供審查，不自動修改。
- 先持久備份，再重讀 policy；任何內容或 etag 漂移都中止。備份失敗時不寫入 Azure。
- 單次 `waf-policy update --custom-rules @file` 寫入完整合併結果，不會逐條建立只有 header 條件的暫態 Block 規則。
- 以 `wait --updated --timeout 600` 有限等待，之後讀回比對規則及非目標設定。這是控制平面驗證，不代表各邊緣節點已傳播完成。
- 更新失敗、等待逾時或讀回不符時，非零結束並保留備份；不自動用舊快照覆寫回滾。請先確認 Azure 的實際狀態，不要盲目重試。

**併發限制：**更新前重讀不是原子的 If-Match 鎖定。CLI 內部也可能讀取後再寫入；最後一次檢查與寫入之間仍有競態。請安排沒有其他 policy 寫入者的變更窗口。

## 套用後驗證

腳本會在本次備份目錄留下原始 policy、原 custom rules、合併結果、實際新增規則清單、manifest，以及寫入後讀回內容。只有完整讀回驗證通過，manifest 的 `controlPlaneVerified` 才會變為 `true`。

```bash
az network front-door waf-policy show \
	--subscription '<subscription-name-or-id>' \
	--resource-group '<resource-group>' \
	--policy-name '<existing-php-waf-policy>' \
	--query 'customRules.rules[?priority >= `500` && priority <= `502`]' \
	--output json
```

在授權的測試網域逐條驗證，先等待設定傳播，再測試組合：

1. 一般合法請求、無害 multipart 上傳及合法 form 請求作為控制組。
2. multipart 的無害文字欄位包含 `PHP_SESSION_UPLOAD_PROGRESS`，預期命中 500；不必放入任何利用程式碼。
3. 19、20、21 層 URL-encoded 欄位及 multipart 欄位（含帶引號名稱），核對 501、502 的 Log 命中及合法流量影響。
4. 查詢既有 WAF 記錄的 rule name、action、時間及請求關聯資訊。不能只用 HTTP 200／403 判斷，因為可能有自訂封鎖狀態碼或其他規則介入。

本工具不建立 diagnostic settings 或監控資源；若沒有 WAF 記錄，就尚未完成資料平面驗證。確認無誤判後才擴大流量，並持續完成 PHP 升級。

## 人工還原

不要將原始完整 policy 或原 custom rules 直接覆寫回 Azure，否則可能抹除後續變更。以下流程僅適用於**成功套用且 manifest 已驗證**的那一次變更；若更新失敗、逾時或驗證失敗，先人工釐清實際 Azure 狀態。

1. 以該次 manifest 的 `resourceId` 核對同一個目標；確認沒有其他寫入者。
2. 使用 `waf-policy show` 取得最新 policy 到 `latest-policy.json`，不要使用舊快照當作目前狀態。
3. 以下 jq 只移除本次 `added-rules.json` 記錄的新增規則，且要求它們仍與本次 `verified-after.json` 的內容完全一致。任一規則被修改、改名、移除或重複時就停止；不刪除套用前已存在而略過的規則。

在權限受限的工作目錄執行，設定 `backup` 指向本次備份目錄：

```bash
umask 077
backup='/secure/path/to/php2shell-TIMESTAMP.SUFFIX'
jq --slurpfile manifest "$backup/manifest.json" \
	 --slurpfile added "$backup/added-rules.json" \
	 --slurpfile after "$backup/verified-after.json" '
	. as $latest
	| if $manifest[0].controlPlaneVerified != true
			 or .id != $manifest[0].resourceId
			 or .provisioningState != "Succeeded"
		then error("備份未驗證、目標不符或 policy 尚未就緒")
		elif all($added[0][];
			.name as $name
			| [$latest.customRules.rules[]? | select(.name == $name)] as $now
			| [$after[0].customRules.rules[]? | select(.name == $name)] as $installed
			| ($now | length) == 1 and ($installed | length) == 1
				and $now[0] == $installed[0])
		then .customRules
			| .rules |= map(select(.name as $name | all($added[0][]; .name != $name)))
		else error("新增規則已有漂移，停止還原") end
' latest-policy.json > restore-custom-rules.json
```

4. 人工比對候選結果，確認只移除當次新增規則，其餘最新規則均保留；再次讀取 Azure 為 `recheck-policy.json`。
5. 下列防護要求候選檔合法且兩次讀取內容完全相同，才允許寫入；仍有前述非原子競態限制。三個目標參數必須與 manifest 一致。

```bash
jq -e '.rules | type == "array"' restore-custom-rules.json >/dev/null &&
jq -e --slurpfile before latest-policy.json '. == $before[0]' recheck-policy.json >/dev/null &&
az network front-door waf-policy update \
	--subscription '<subscription-name-or-id>' \
	--resource-group '<resource-group>' \
	--policy-name '<existing-php-waf-policy>' \
	--custom-rules @restore-custom-rules.json --no-wait
```

6. 對同一目標執行 `waf-policy wait --updated --timeout 600`，再 `show` 確認還原結果、其他設定與流量。還原後也須重新評估 PHP 暴露風險。

## 覆蓋限制

- 合法使用 PHP session upload progress 的應用會受 500 影響；本文或可被檢查的上傳內容若含無害 token，也可能誤判。
- Front Door 本文、檔案檢查有 128 KB 邊界，不能保證檢查整個大檔或所有編碼、攻擊路徑。
- 可直接連到 origin 的流量不會經過此 Front Door WAF；請另行確認 origin 存取限制。
- `policySettings.requestBodyCheck` 的官方說明針對 managed rules，不能把它直接當成 custom RequestBody 的啟停開關；此工具不調整它。
- 三條規則只減少部分攻擊面，無法完整保護原文所述的兩個漏洞。升級 PHP 仍是完整修復。

## 本機測試

```bash
/bin/bash -n mitigate-php2shell.sh
/bin/bash -n tests/test-mitigate-php2shell.sh
./tests/test-mitigate-php2shell.sh
shellcheck mitigate-php2shell.sh
shellcheck --exclude=SC2016 tests/test-mitigate-php2shell.sh
```

測試以 mock `az` 覆蓋預覽、合併、重跑、衝突、配額、Allow／狀態保護、缺相依工具、登入／讀取失敗、備份失敗、併發漂移、更新失敗、逾時及讀回不符，不連線 Azure。SC2016 僅在測試檔排除，因 fixtures 刻意使用單引號保留 jq 變數。

Regex 邊界測試使用 jq 的 Regex 引擎與無害資料，並不證明 Azure WAF 引擎、本文解析、記錄設定或實際流量已驗證；仍須進行上述授權環境測試。

## 參考資料

- [Microsoft PHP2Shell WAF 規則原文](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684)
- [Azure CLI Front Door WAF policy 命令](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy?view=azure-cli-latest)
- [Front Door WAF custom rules 語意與優先順序](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-custom-rules)
- [Front Door 服務限制](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits#azure-front-door-standard-and-premium-service-limits)