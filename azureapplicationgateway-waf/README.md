# azureapplicationgateway-waf

透過 Azure CLI，將三條 PHP2Shell 緩解規則加入**既有 PHP 專用 Azure Application Gateway WAF policy**。操作方式與同儲存庫的 Front Door 工具一致：預設預覽並備份，明確指定 `--apply` 才寫入，支援獨立備份與完整 custom rules 回滾。不建立 policy，也不修改 gateway、listener、path 綁定或其餘設定。

依據 [Microsoft 原文（2026-10-21，版本 2.0）](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684)的 **Application Gateway** 定義，不直接複製 Front Door 規則。這是暫時緩解措施，完整修復仍須升級至已修補的 PHP 版本。

## 結構與規則

```text
azureapplicationgateway-waf/
  .gitignore
  mitigate-php2shell.sh
  php2shell-rules.json
  README.md
  tests/
    test-mitigate-php2shell.sh
```

規則集中於 [php2shell-rules.json](php2shell-rules.json)。各規則的兩個條件為 AND。

| Priority | 名稱 | 動作 | 比對內容 |
| --- | --- | --- | --- |
| 90 | BlockPhpSessionUploadProgress | Block | multipart header 與 PostArgs 中的 `php_session_upload_progress`，不分大小寫 |
| 91 | PhpFormNesting20 | Log | URL 解碼後的 form 本文包含至少 20 層方括號參數 |
| 92 | PhpMultipartNesting20 | Log | multipart 的 PostArgs 欄位名稱包含至少 20 層方括號參數 |

`Log` 只記錄、不封鎖，並繼續評估後續規則。20 層是應用政策門檻，不是漏洞的保證邊界；確認合法流量相容性後，才另行考慮將 Log 改為 Block。本工具不自動升級動作。

與 Front Door 的差異：Application Gateway priority 範圍為 1–100，故採原文 90–92，不使用 500–502；`customRules` 是陣列，使用 `state`、`matchVariables`、`matchValues`、`Regex` 與 API 原有拼字 `negationConditon`。session 與 multipart 規則使用 `PostArgs`；multipart Regex 針對解析後欄位名稱，不是完整 Content-Disposition 文字。

## 前置需求

- Bash 3.2 以上、Azure CLI 2.75.0 以上、jq 1.6 以上，適用 macOS、Linux 與 Azure Cloud Shell Bash。
- Application Gateway WAF_v2 與既有 WAF policy；policy 本身沒有 Front Door 的 SKU 欄位。本工具不修改或推測所連 gateway 的 SKU。
- Azure 登入及目標 policy 的讀取權限，套用另需寫入權限，例如適當範圍的 Network Contributor；Azure Policy 是否允許更新由服務判定。
- 新增緩解規則時要求 `policySettings.state: Enabled`、`mode: Prevention`、`provisioningState: Succeeded`，且 `applicationGateways`、`httpListeners` 或 `pathBasedRules` 至少存在一個綁定參照。
- 人工確認實際有效 policy 僅涵蓋受影響 PHP 網域與路徑，包含沒有 `.php` 副檔名的路徑。listener／path policy 可能覆寫 gateway 層級 policy，不能只憑綁定存在就判定所有流量受保護。

此命令群組為 Azure CLI 內建，不需要 `front-door` extension。腳本不自動安裝、登入或切換全域訂用帳戶。

```bash
az login
az version
jq --version
chmod +x mitigate-php2shell.sh tests/test-mitigate-php2shell.sh
```

## 操作

在本目錄執行，替換三個目標參數：

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>'
```

預設為 `--dry-run`。讀取並核對資源 ID 與資料格式後立即建立持久備份，再顯示新增／略過清單、完整合併結果與套用阻礙。Disabled、Detection、無綁定等狀態仍可預覽；衝突或配額超限以非零狀態停止並保留原始快照。備份失敗即停止。

確認範圍、誤判風險與變更內容後，以相同參數加上 `--apply` 套用。只要備份既有規則則加 `--backup-only`；不可與 `--dry-run`、`--apply` 或 `--rollback` 混用。

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>' \
  --apply
```

可加 `--backup-dir '/secure/path'` 改變備份根目錄。預設為腳本旁的 `backups/POLICY_NAME/php2shell-TIMESTAMP.SUFFIX/`；每次使用獨立目錄，不覆寫舊備份。目錄權限為 700，檔案預設 600。備份可能含敏感設定；自訂目錄不會自動加入 Git 忽略清單。`--help` 不需登入。

### 強制套用

確認風險後，使用 `--force --apply` 略過套用前置警告，包含 Disabled、Detection、非 Succeeded（含 Updating／Failed／未知狀態）、缺少綁定與較早的 Allow：

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>' \
  --force --apply
```

警告仍會列出，不需互動確認；`--force` 單獨使用或搭配 `--dry-run` 仍只預覽，不寫入。備份 manifest 的 `force` 欄位記錄是否指定此參數。`--force` 只適用新增緩解規則，不能搭配 `--backup-only` 或 `--rollback`；回滾覆寫後續變更仍使用 `--force-rollback`。

**強制寫入不代表緩解生效：**腳本不會啟用 policy、改為 Prevention、建立綁定或移除 Allow；Azure 仍可能拒絕正在更新或其他不合法狀態的更新。登入與目標驗證、規則格式、同名／priority 衝突、配額、備份、寫入前漂移與寫入後驗證均不可略過。服務失敗仍以非零狀態結束，不自動回滾。

### 更新保護

- 保留既有非目標 custom rules、managed rules、tags、location、policy settings 與綁定，不修改 `requestBodyCheck`。
- 同名同內容略過，容忍空值、缺省 state／transforms 與空 selector；全部相同則零寫入。同名異內容或大小寫碰撞停止，不會把人工提升的 Block 降回 Log。
- priority 90、91、92 衝突停止，不自動換號；檢查名稱與 priority 重複、100 條規則、priority 1–100 與每條最多 10 個條件。不套用 Front Door 的五條 Regex 規則限制。
- 較早且啟用的 Allow 預設阻止套用，可用 `--force` 略過；其他較早終止動作列出完整條件供審查。Disabled Allow 不阻止套用。
- 列出所有套用前置條件問題、目前值（缺少時為 `null`）與要求值；不自動啟用 policy、切換模式或調整綁定。
- 先備份再重讀；內容或 etag 漂移即停止。單次 `waf-policy update --custom-rules @file` 寫入完整陣列，不逐條建立暫態規則。
- 此 CLI 更新命令不支援 `--no-wait`；更新返回後執行 `wait --updated --interval 10 --timeout 600`，再讀回比對規則與非目標設定。600 秒只限制 wait 階段，不是整次 CLI 更新的逾時。
- 更新失敗、等待逾時或讀回不符即非零結束，保留備份且不自動回滾。請確認 Azure 實際狀態，不要盲目重試。

**平行寫入限制：**更新前重讀不是原子的 If-Match 鎖定，CLI 也可能內部先讀後寫；最後檢查至寫入間仍有競態，須安排沒有其他 policy 寫入者的變更窗口。

## 備份與回滾

| 備份檔案 | 內容 |
| --- | --- |
| original-policy.json | 原始完整 policy，供核對，不整份還原 |
| original-custom-rules.json | 操作前完整 custom rules 陣列，回滾目標 |
| merged-custom-rules.json | 預期寫入陣列；獨立備份時等於原始規則 |
| added-rules.json | 本次新增規則；獨立備份與回滾時為空陣列 |
| manifest.json | 資源 ID、時間、操作、模式、回滾來源與驗證狀態 |
| verified-after.json | 寫入後讀回內容；未進入此階段則不存在 |

只有完整寫入後驗證成功才設定 `controlPlaneVerified: true`。預覽與獨立備份的此欄位為 false，不代表備份失敗。只使用本工具產生且可信任、未經修改的完整備份目錄；Front Door 備份不相容。

以相同三個目標參數，加 `--rollback` 預覽回滾，確認後再加 `--apply`：

```bash
./mitigate-php2shell.sh \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --policy-name '<existing-php-waf-policy>' \
  --rollback './backups/<existing-php-waf-policy>/php2shell-TIMESTAMP.SUFFIX'
```

回滾還原該次操作前的**完整 custom rules**，不只是移除 90–92；其餘目前設定維持不變。先核對 manifest／原始 policy 的資源 ID、陣列格式及內容一致性，目前規則已等於快照時零寫入。

目前規則須與來源備份的預期合併結果一致，否則拒絕；只有明確加 `--force-rollback --apply` 才覆寫後續變更。force 不略過資源核對、備份驗證、目前狀態與寫入前漂移檢查。可先不加 `--apply` 預覽強制回滾。

回滾只允許目前狀態為 Succeeded 或 Failed，不受 Disabled、Detection 或無綁定影響。回滾前會建立目前狀態的新備份，來源快照不會變動；必要時可用新備份復原回滾前規則。失敗不連鎖重試或自動回滾。

一般使用該次套用的備份；成功完成的 dry-run 備份也能在實際規則與預期結果一致時回滾。預覽提早失敗的快照不代表已完成合併。獨立備份無法預測之後變更，還原已變動規則通常需要 force。更新逾時留下的未驗證備份亦可使用，但須先確認 Azure 已停止更新，未知或部分結果需人工核對後才強制還原。

如需保留後續新增規則而只移除這次新增者，請人工比對 `added-rules.json` 與最新讀回內容；不要將完整舊快照直接覆寫回 Azure。

## 套用後驗證與限制

```bash
az network application-gateway waf-policy show \
  --subscription '<subscription-name-or-id>' \
  --resource-group '<resource-group>' \
  --name '<existing-php-waf-policy>' \
  --query 'customRules[?priority >= `90` && priority <= `92`]' \
  --output json
```

控制平面成功不代表資料平面已完成傳播。等待設定生效後，在授權測試環境測試合法請求與無害 multipart 控制組、含 session token 的表單，以及 19／20／21 層 form／multipart 欄位，逐條核對 WAF 記錄的規則名稱、動作、時間與請求關聯資訊。不能只憑 HTTP 200／403 判斷。回滾後亦需驗證實際流量。

本工具不建立 diagnostic settings。未取得 WAF 記錄就尚未完成資料平面驗證；離線測試使用 jq Regex 引擎，不能取代 WAF 的實際比對、PostArgs 解析或傳播驗證。

合法 session upload progress 與深層參數可能誤判。本文／檔案檢查受引擎版本、policy 設定、檢查大小與內容類型限制；PostArgs 也只涵蓋 WAF 可解析且提供檢查的內容，不能保證所有編碼或大檔皆受保護。不要套用 Front Door 固定 128 KB 邊界到 Application Gateway。繞過 gateway 直連後端的流量不受此 policy 保護，須另行限制。三條規則均非完整漏洞修補，仍須升級 PHP。

## 本機測試

```bash
/bin/bash -n mitigate-php2shell.sh
/bin/bash -n tests/test-mitigate-php2shell.sh
./tests/test-mitigate-php2shell.sh
shellcheck mitigate-php2shell.sh
shellcheck --exclude=SC2016 tests/test-mitigate-php2shell.sh
```

測試使用嚴格 mock `az`，檢查 Application Gateway 命令與規則欄位，涵蓋預覽、備份、合併、重跑、衝突、配額、Allow、狀態與各層綁定、回滾、損壞備份、漂移、更新／等待／驗證失敗及 Regex 邊界，不呼叫真實 Azure。SC2016 僅在測試檔排除，因 fixture 刻意用單引號保留 jq 變數。

官方參考：[CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy?view=azure-cli-latest)、[自訂規則](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/custom-waf-rules-overview)、[本文大小與檔案限制](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits)。