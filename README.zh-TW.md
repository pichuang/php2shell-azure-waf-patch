# Azure Front Door 與 Application Gateway：PHP WAF 緩解措施操作手冊

## TL;DR

> **務必先備份既有 WAF 設定，再進行任何部署或變更。** 請依[共用準備作業](#共用準備作業)匯出原則，保留自訂規則、受控規則覆寫與原則設定；若會變更 Application Gateway 回應重寫，也要備份閘道的重寫規則集及路由關聯。確認備份完整、可讀，並備妥復原計畫後才能繼續；備份失敗或內容不完整時，請勿部署。

1. **依平台套用暫時防護：** 以 Azure CLI 執行 [Front Door](#azure-front-door-waf) 或 [Application Gateway](#azure-application-gateway-waf_v2) 步驟，保留既有規則，確認 PHP 路由範圍、Enabled/Prevention 狀態及較早執行的 Allow 規則。套用上傳進度基準，並依平台評估大小限制與回應防護；巢狀層數規則先維持 Log。
2. **無法立即調整 PHP 時，評估緊急圍堵：** 若無法排除 CVE-2026-115560 的漏洞條件，可經核准在受影響 PHP 範圍內暫時封鎖 multipart。這會中斷合法上傳與 multipart 表單，也不代表三個漏洞已完整修補。
3. **先在預備環境驗證，再部署正式環境：** 依[資料平面驗證](#資料平面驗證)確認要求封鎖、回應行為、登入與上傳影響，並演練[元件復原](#依元件復原)。設定讀回成功不等於防護已生效；Front Door 回應規則 99006001 不提供 WAF 記錄或命中次數。
4. **同步推進 PHP 修補：** WAF 只是暫時圍堵。請由執行環境負責人確認各 CVE 的適用修補或緩解措施，更新所有提供服務的執行環境與容器映像；不要假設前兩個漏洞的修補版本也修補了 CVE-2026-115560。

## WhatHappen

以下文字可使用區塊的複製按鈕，一次貼到 Teams 或通訊軟體彙報。

```text
【PHP2Shell 風險與建議應對｜資訊檢閱日期：2026-10-24】

發生什麼事？
PHP 公布三個相關漏洞（CVE-2026-109618、CVE-2026-109619、CVE-2026-115560）。白話來說，特定情況下，PHP 在處理記憶體不足、清理前一次要求留下的資料，或處理上傳進度與工作階段資料時，可能出錯。攻擊者若滿足相關條件，可能讓網站服務當機，甚至在伺服器上執行未經授權的程式碼。不是所有 PHP 網站都符合相同條件，仍須盤點版本、設定與應用程式行為；這份通知不代表已確認我們遭到入侵。

建議採取措施：
1. 任何部署前，務必先備份既有 Azure WAF 設定，確認備份完整且可讀，並備妥復原計畫。若會調整 Application Gateway 回應重寫，也要備份重寫規則與路由關聯；備份失敗就不要部署。
2. 請系統負責人同步盤點 PHP 版本、設定及容器映像，確認各漏洞適用的修補或緩解方式，安排更新。不要假設修好前兩個漏洞的版本，也已修好 CVE-2026-115560。
3. 先以 Azure Front Door 或 Application Gateway WAF 加上暫時防護，保留既有規則，確認防護涵蓋受影響的 PHP 路由，並限制繞過 WAF 直接連到來源站的存取。大小限制及回應防護須依平台能力與可用性設定。
4. 若無法立即調整 PHP，且無法排除 CVE-2026-115560 的漏洞條件，可經核准暫時封鎖受影響 PHP 路由的 multipart 要求（常見於檔案上傳）。這會中斷合法上傳與部分表單，必須先確認業務影響。
5. 先在預備環境確認封鎖效果、登入與上傳影響，並演練復原，再部署正式環境。設定成功不等於防護已驗證；WAF 只是降低風險，不能取代 PHP 修補，也不能保證擋住所有利用方式。

請相關負責人回報：受影響網站與版本、備份及驗證結果、預計變更時間、上傳中斷影響、修補負責人與完成期限。尚未確認的項目請標示「待確認」，不要將規劃中的措施列為已完成。
```

公告檢閱日期：**2026-10-24**。

請從您使用的平台開始閱讀。本文以直接執行 Azure CLI 為主要操作方式，說明 CVE-2026-109618、CVE-2026-109619 與 CVE-2026-115560 的建議設定；儲存庫腳本則列在後方，作為選用的替代方式。Azure WAF 提供的是暫時性的補償性控制措施，不能修補 PHP 本身的漏洞。既有規則定義與部署腳本均維持不變。請只執行適用於您平台的指令；若應用程式同時受到兩項產品保護，應分別設定並驗證每一層。

## 建議設定

| 漏洞 | Azure Front Door WAF | Application Gateway WAF_v2 |
| --- | --- | --- |
| CVE-2026-109618 | 若可接受上傳功能暫停，則封鎖 multipart；否則必須由上游或來源站在 PHP 解析前強制執行限制。Front Door 的 128 KB 檢查深度並不是整個要求的大小限制。 | 啟用要求本文檢查、非檔案本文大小限制及檔案上傳限制，並採用經核准的保守數值。需要更強的圍堵措施時，封鎖 multipart。 |
| CVE-2026-109619 | 套用上傳進度基準規則；需要更強的圍堵措施時，另外加入 multipart Block 規則。回應受控規則 `99006001` 可用時，也應評估啟用。 | 套用上傳進度基準規則；需要更強的圍堵措施時，另外加入 multipart Block 規則，並加入具條件的回應 Cookie 重寫規則。 |
| CVE-2026-115560 | 若無法套用 PHP 執行環境的緩解措施，且無法排除符合漏洞條件的設定，則在受影響的 PHP 路由範圍內暫時封鎖 multipart。 | 同樣在受影響的 PHP 路由範圍內暫時封鎖 multipart。 |

**操作取捨：** 若無法變更 PHP 設定，緊急封鎖 multipart 是本文提供的最強要求端圍堵選項，但會中斷合法上傳與 multipart 表單。回應端控制屬於 PHP2Shell 的額外縱深防禦，並不是這三個 CVE 的專用修補。在完成流量評估前，請將巢狀層數規則維持為 **Log**；改成 Block 並不代表已完成修補。

- [Azure Front Door 設定](#azure-front-door-waf)：基準規則、緊急封鎖、受控回應防護及設定讀回確認。
- [Application Gateway 設定](#azure-application-gateway-waf_v2)：大小限制、基準規則、緊急封鎖、回應重寫及設定讀回確認。
- 設定章節之後提供[驗證](#資料平面驗證)、[復原](#依元件復原)及[漏洞與來源詳細說明](#漏洞詳細說明與修補)。

## 共用準備作業

請在儲存庫根目錄以 Bash 執行範例，並替換所有預留值。使用 Azure CLI 2.75.0 以上版本及 jq 1.6 以上版本，並確認已安裝的 CLI 支援下列參數。Front Door 指令需要 `front-door` 擴充功能。

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

執行任何寫入操作前：

- 確認實際生效的原則僅涵蓋預期的 PHP 網域與路由，包括不含副檔名的路由。關聯清單有內容，不代表所有流量都會經過該原則。
- 原則必須已啟用，且處於 **Prevention** 模式，才能實際執行封鎖。變更模式會影響所有適用規則，因此必須先取得核准。
- 檢查較早執行、命中後會終止後續評估的 `Allow` 規則。優先序數字越小，越早執行；若先命中 `Allow`，可能略過本文建議的控制措施。
- 封鎖直接存取來源站的路徑，並檢查替代入口與容錯移轉路徑。繞過 WAF 的要求不受其保護。
- 備份原則、檢查預定變更，並安排沒有其他人同時修改原則的變更時段。CLI 的讀取、修改、寫回流程不是不可分割的鎖定操作，無法防止同時寫入。
- 確認已具備要求端 WAF 診斷記錄，以及來源站的存取與錯誤記錄。回應規則 `99006001` 是明確的例外：它不產生 WAF 記錄，也不提供命中次數。讀回設定只能確認控制平面狀態，不能證明資料平面已實際防護。

在變更自訂規則、原則大小限制、受控規則覆寫設定，或重寫規則集與其關聯前，請直接使用 Azure CLI 備份。下列指令只會讀取 Azure，並在本機寫入限制存取權限的快照，不會變更 Azure。只執行適用於您平台的 `az ... show` 與對應 `jq` 指令。若指令失敗，或快照無效、內容為空，請立即停止。備份應存放於限制存取的位置，不要提交至 Git，也不要以整份資源還原的方式覆蓋後續變更。請保留輸出顯示的備份目錄，供後續平台步驟使用。

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

請使用現有且範圍限定於受影響 PHP 網域與路由的原則。以下所有寫入操作都必須先完成共用準備作業、備份及核准。依賴 Block 動作前，請確認實際生效的設定為 **Enabled + Prevention**，並驗證安全性原則、網域與路徑的關聯。不要替換整份原則，也不要直接以基準規則取代整個自訂規則集合。

### 1. CVE-2026-109619：套用上傳進度基準規則

先用 Azure CLI 讀取目前原則，再透過 jq 合併既有的 [Front Door 規則定義](azurefrontdoor-waf/php2shell-rules.json)。這份 JSON 是設定資料，不是可執行腳本。基準包含三條規則：優先序 500 的上傳進度 **Block** 規則，以及優先序 501、502 的巢狀層數 **Log** 規則。不要只將基準檔案直接傳給 `--custom-rules`，因為這會取代整個集合，可能刪除其他規則。

以下準備流程不會變更 Azure。它會檢查 Enabled/Prevention 狀態、保留其他規則與自訂規則集合的其他屬性，並在名稱或優先序衝突時停止，而不是覆寫。如果基準規則已存在，請先檢查其定義，再採取另外審查過的更新方式；不要為了重跑這個首次安裝範例而刪除既有規則。繼續前，請檢查較早執行的 Allow 規則及規則配額。發生任何錯誤都應停止；所有準備檢查成功後，才能執行套用區塊。

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

請檢查合併後的**完整** JSON，包括較早執行且會終止後續評估的 Allow 規則，以及所有其他規則項目。套用前立即重新讀取原則並比對。若檢查失敗或出現差異，請停止，改以變更後的原則重新規劃。這只能偵測已觀察到的設定差異，不是不可分割的 If-Match 鎖定，因此仍須維持無其他人同時寫入的變更時段。

```bash
az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--output json > "$RESPONSE_BACKUP/frontdoor-baseline.preapply.json" &&
diff -u <(jq -S . "$RESPONSE_BACKUP/frontdoor-baseline.before.json") \
	<(jq -S . "$RESPONSE_BACKUP/frontdoor-baseline.preapply.json")
```

**取得核准後才可選擇執行的寫入操作：** 只套用已審查的合併後自訂規則集合。不要在此步驟一併變更受控規則、原則設定或 SKU。任何指令失敗都應停止；請讀回並比對所有自訂規則，而不只是上傳進度規則。

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

確認原有規則、原則設定與受控規則都未改變，且三條基準規則的動作與條件符合預期。讀回設定不是資料平面測試。Front Door 基準規則會在受檢查的 `RequestBody` 中比對預設標記。請確認實際的 `session.upload_progress.name`，測試只有欄位名稱含標記的情況，並且不要假設檢查範圍之外也受到保護。需要更強的圍堵措施時，請使用步驟 2。

### 2. CVE-2026-115560 與加強圍堵：封鎖 multipart

如果無法排除符合漏洞條件的 PHP 設定，且無法在執行環境停用上傳進度功能，請在受影響的 PHP 範圍內暫時封鎖宣告為 `multipart/form-data` 的要求。這也能降低 CVE-2026-109618 與 CVE-2026-109619 相關的 multipart 暴露風險，但無法封閉所有利用路徑。合法的 multipart 表單與上傳功能也會停止運作。

**選用寫入操作：** 規則名稱必須尚未使用，優先序 `499` 也必須未被占用，且早於**所有**可能匹配、命中後會終止後續評估的 Allow 規則。請檢查配額。若使用共用原則，應在初次建立規則時就加入經核准的主機與路徑條件，而不是直接套用此未限定範圍的範例。不要覆寫既有規則。

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

### 3. CVE-2026-109618：要求大小限制的能力邊界

Front Door **不提供** Application Gateway 的要求本文與上傳限制參數。其 128 KB 本文檢查邊界並不是可設定、用來拒絕整個解碼後要求的大小上限。不要自行假設 Front Door 有對應的 `--max-request-body-size-in-kb` 參數，也不要只依賴 `Content-Length`，或假設自訂條件能量測所有未經檢查的位元組。

若可以中斷 multipart 上傳，請使用步驟 2。否則必須由具備能力的上游或來源站，在 **PHP 解析前**強制限制解碼後大小、part 數量、每個 part 的標頭數量、輸入項目數量及巢狀層數。若沒有可用的限制機制，請記錄防護缺口，並升級處理隔離或修補需求；單靠 WAF 原則無法確認不會發生記憶體不足問題。

### 4. PHP2Shell 額外防護：啟用回應規則 99006001

Microsoft 預計於 **2026 年 10 月 28 日**完成推出。截至本手冊的 10 月 24 日檢閱日期，請確認實際可用性，不要假設規則已經存在。此規則**預設停用**，位於 DRS 2.0、2.1、2.2 的 `MS-ThreatIntel-Response-CVEs` 群組。Front Door Standard 支援自訂規則，不代表支援受控 DRS；請使用 Premium 等支援的 SKU。不要只為執行此範例，就升級或替換已附加的 DRS。

```bash
az network front-door waf-policy managed-rule-definition list \
	--subscription "$SUBSCRIPTION" --output json

az network front-door waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--query '{sku:sku,settings:policySettings,managed:managedRules}' --output json
```

請在**已附加**的 `Microsoft_DefaultRuleSet` 版本中找到 `99006001`。若不可用或服務拒絕此設定，請保留要求端圍堵措施，將回應防護記錄為**尚不可用**，並向 Microsoft 確認推出進度。不要自行建立使用相同 ID 的自訂規則。

**選用寫入操作：** 完成備份並取得核准後，只有在目標覆寫項目尚不存在，且已確認安裝的 CLI 能在新增指定項目時保留現有群組與規則，才可執行下列指令。若項目已存在，請使用經審查的合併方式，或在入口網站編輯該規則，不要重複新增。請保留排除項目、敏感度及其他所有覆寫設定。

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

將完整的受控規則集合與快照比對，應只有預定的覆寫項目發生變更。確認 `enabledState=Enabled`、`action=AnomalyScoring`，以及入口網站動作為 **Block on anomaly**；這是 Microsoft 對此回應規則要求的動作。不要以一般的 `Block`、`Log` 或挑戰動作替代。規則集層級的異常動作應另外檢查，不要未經說明就變更所有規則的行為。

此規則會移除回應中疑似惡意的元素，並回傳其餘內容；不要預期它像要求端封鎖一樣回傳 403。它**不產生 WAF 記錄，也不提供命中次數**。請使用後面的回應差異驗證；只讀回設定或使用一般無效 Cookie 測試資料，不能證明這個未公開的受控特徵已生效。這是縱深防禦，不代表三個 CVE 中任何一個已完成修補。

## Azure Application Gateway WAF_v2

請使用現有且限定於 PHP 範圍的 WAF 原則，以及實際閘道的路由與重寫資源。閘道與 WAF 原則可能位於不同的資源群組。以下所有寫入操作都必須先完成共用準備作業、備份及核准。這些是 **Application Gateway v2** 的建議，不是 Application Gateway for Containers 的指令。

### 1. CVE-2026-109618：強制限制要求與上傳大小

若使用 Application Gateway WAF_v2，並搭配 CRS 3.2 或相容的較新引擎，可透過以下**選用寫入操作**啟用本文檢查與大小限制。範例允許最多 128 KB 的非檔案要求資料，以及 32 MB 的檔案上傳上限。這些只是業務限制的示範值，不是針對漏洞保證安全的數值。若目前限制更嚴格，不要只為配合範例而放寬。

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

要求本文檢查深度、要求大小限制與檔案上傳限制是不同的控制措施。檔案內容與非檔案要求資料分開處理；以上設定並不會將整個 multipart 要求限制在 128 KB。也請檢查官方文件所述的檔案大小限制緩衝範圍。需要復原時，應依備份逐項還原設定；刪除自訂規則不會還原原則設定。

### 2. CVE-2026-109619：套用上傳進度基準規則

既有的 `BlockPhpSessionUploadProgress` 規則已使用 **Block** 動作，用來限制包含預設上傳進度標記的 multipart 要求；另外兩條巢狀層數規則並未涵蓋所有殘留狀態的利用路徑。

請使用 Azure CLI 與 jq 讀取並合併既有的 [Application Gateway 規則定義](azureapplicationgateway-waf/php2shell-rules.json)。**基準包含全部三條規則**，不是特定 CVE 的完整修補：優先序 90 為 Block，優先序 91、92 為 Log。不要只將此檔案直接傳給 `--custom-rules`，因為這會取代整個自訂規則集合。以下準備流程會保留其他項目，並在名稱或優先序衝突時停止。若基準已安裝，應採用經審查的更新方式，而不是此首次安裝範例。請檢查較早執行的 Allow 規則與配額；發生任何錯誤都應停止。

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

請檢查合併後的完整 JSON 及其對應用程式的影響。套用前立即重新讀取原則；若失敗或出現任何差異，請停止。此快照是在步驟 1 經核准的大小設定變更**之後**取得，因此不會重用變更前的過期原則。此檢查無法以不可分割的鎖定操作防止同時修改。

```bash
az network application-gateway waf-policy show \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --name "$AG_POLICY" \
	--output json > "$RESPONSE_BACKUP/application-gateway-baseline.preapply.json" &&
diff -u <(jq -S . "$RESPONSE_BACKUP/application-gateway-baseline.before.json") \
	<(jq -S . "$RESPONSE_BACKUP/application-gateway-baseline.preapply.json")
```

**取得核准後才可選擇執行的寫入操作：** 只更新已審查的合併後自訂規則陣列，再讀回原則設定、受控規則及所有自訂規則，確認沒有非預期變更。請確認原有項目全部保留，且三條基準規則的動作與條件符合預期。任何指令失敗都應停止。

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

請盤點各 PHP 集區與網站實際使用的 `session.upload_progress.name`；基準使用預設值 `PHP_SESSION_UPLOAD_PROGRESS`。自訂名稱必須另外審查防護涵蓋範圍。Application Gateway 使用解析後的 `PostArgs`。請以只有欄位名稱含標記、欄位值為一般文字的無害要求測試；不要假設規則涵蓋所有編碼或超出檢查大小的要求。

### 3. CVE-2026-115560 與加強圍堵：封鎖 multipart

PHP 官方記載的緩解措施是 `session.upload_progress.enabled=0`。若您無法變更此設定，也無法排除符合漏洞條件的組合，可在受影響的 PHP 範圍內，緊急封鎖所有宣告為 `multipart/form-data` 的流量。這會犧牲合法上傳與 multipart 表單功能，但不必依賴進度欄位名稱，也不受該欄位在受檢查本文中位置的影響。

以下是對**現有原則的選用寫入操作**，會新增獨立規則，不修改基準規則。只適用於已限定 PHP 範圍的原則。若為共用原則，應先設計並驗證額外的主機與路徑條件；不要先建立大範圍封鎖，再補上適用範圍。

請確認 `EmergencyBlockPhpMultipart` 尚不存在。優先序 `89` 必須未被占用，且早於所有可能匹配受影響流量的 Allow 規則。比基準規則早執行，不代表比所有 Allow 規則都早。若發生衝突，請停止，不要覆寫或自動重新編號。套用前，請檢查規則配額與現有條件。

完整條件會在同一次建立操作中提供。以下的 `negationConditon` 拼字沿用本儲存庫使用的 Application Gateway 規則結構。

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

這些依標頭判斷的規則不依賴本文檢查深度，但仍取決於正確的原則範圍、執行順序、設定傳播，以及 WAF 與 PHP 對標頭的一致解讀。它們不能證明漏洞已完全緩解。如果無法接受這些不確定性，請透過另外核准的隔離變更，暫時拒絕外部存取受影響的 PHP 服務。

### 4. PHP2Shell 額外防護：重寫可疑的 Set-Cookie

請原樣使用 Microsoft 10 月 22 日指南公布的下列運算式，比對的是**回應**中的 `Set-Cookie` 值，不是要求中的 `Cookie` 標頭：

```text
^PHPSESSID=(?:[a-zA-Z0-9-]|%2[Cc])*(?:[^a-zA-Z0-9;%-]|%(?!2[Cc]))+[a-zA-Z0-9-]*[^;]+;
```

此運算式針對預設且區分大小寫的 `PHPSESSID` Cookie 名稱。請盤點實際的 `session.name`；自訂名稱需要另外審查運算式並執行回歸測試。這是針對特定特徵的啟發式規則，不是通用的工作階段識別碼驗證器。請在測試中明確保留公布運算式的邊界情況，不要將所有未匹配的值視為安全。此運算式包含負向前瞻，但一般重寫文件建議使用 RE2 相容語法，並說明引擎限制。請在目標閘道與引擎上驗證服務是否接受，以及實際匹配結果。若被拒絕或無效，應停止並向 Microsoft 尋求指引，不要逕自放寬運算式。

寫入前先規劃關聯。Basic 路由規則只能關聯**一個**重寫規則集；路徑式路由則使用 URL 路徑對應的預設重寫設定，以及各路徑規則的重寫設定。若已有規則集，應先檢查共用該規則集的所有路由，再加入名稱唯一、使用未占用順序值的新規則；或透過既有 IaC 流程複製並合併。不要以空的或新建規則集取代既有關聯，導致其他重寫規則遺失。

以下**選用寫入操作**假設已存在經審查的重寫規則集，且規則名稱與執行順序值均可使用。向已關聯的規則集加入規則，會立即影響流量。當回應有多個 `Set-Cookie` 標頭時，`headerValueMatcher` 用來選出匹配的項目；空的標頭值表示刪除。如果只有條件判斷，卻未限定刪除哪一個 `Set-Cookie`，可能連帶移除其他 Cookie，因此不要省略 matcher。請確認 CLI 支援 `--response-header-configurations`，且讀回設定時仍保留 matcher；否則應使用入口網站或經核准的 ARM 設定，不要改用 `--response-headers Set-Cookie=` 作為替代方案。

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

若路由尚無重寫規則集，請先透過入口網站或既有 IaC 流程準備並驗證完整規則集，再關聯至實際 PHP 路由。以下關聯操作**僅適用於 Basic 路由**，屬於選用寫入；若正確的規則集已關聯，就不必執行。路徑式路由應改為設定預期的預設或個別路徑規則關聯，不要假設此 Basic 範例也適用於路徑對應。

```bash
AG_BASIC_RULE='<reviewed-basic-php-routing-rule>'
az network application-gateway rule update \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_GATEWAY_RG" --gateway-name "$AG_GATEWAY" \
	--name "$AG_BASIC_RULE" --rewrite-rule-set "$AG_REWRITE_SET"
```

請確認閘道佈建成功，並讀回完整規則集與路由、路徑對應的參照。與快照比對時，也要檢查規則順序，以及後續規則是否可能重新加入已刪除的標頭。移除匹配的標頭，也會移除其中的 `Path`、`Domain`、`Secure`、`HttpOnly` 與 `SameSite` 屬性；若選擇替換而非刪除，應有意識地替換**整個**值，並驗證這些屬性。不要插入固定且可重複使用的假工作階段識別碼。

復原時，確認目前定義與管理歸屬後，只刪除既有規則集中本次新增的重寫規則。若曾新增規則集或關聯，應先精確還原先前的 Basic、個別路徑或預設關聯，驗證流量，再於沒有任何路由參照時移除新規則集。保留所有原有重寫規則。閘道快照可供審查與還原規劃使用，但不能直接視為可安全執行整份資源 PUT 的內容。復原後，請重新檢查登入、Cookie 及路由行為。

## 依元件復原

確認已完成對應的 PHP 修補或執行環境緩解措施後，請檢查目前的緊急規則，只移除本次變更新增的項目。以下只執行您平台的指令。這些是**選用寫入操作**；若同名規則在本次變更前就已存在，或後來已改作其他用途，請勿執行。確認刪除結果，並保留備份與變更記錄。原有基準規則及原則設定會維持不變。

```bash
az network front-door waf-policy rule delete \
	--subscription "$SUBSCRIPTION" --resource-group "$FD_RG" --policy-name "$FD_POLICY" \
	--name EmergencyBlockPhpMultipart

az network application-gateway waf-policy custom-rule delete \
	--subscription "$SUBSCRIPTION" --resource-group "$AG_RG" --policy-name "$AG_POLICY" \
	--name EmergencyBlockPhpMultipart
```

| 已變更的元件 | 復原要求 |
| --- | --- |
| 基準自訂規則 | 將目前規則集合與該平台的 `*-baseline.before.json` 比對。若為首次安裝，確認目前定義後，使用該平台的自訂規則刪除指令，只移除本次新增且仍由本次變更管理的三條基準規則；保留其他規則及後續變更。完整還原自訂規則可能覆蓋後續變更。選用工具文件說明的是該替代方式，不是單一規則的復原。 |
| Application Gateway 本文與上傳設定 | 依 `application-gateway-policy.json` 逐項還原先前設定；自訂規則還原不涵蓋這些設定。 |
| Front Door 回應規則覆寫 | 只還原 `99006001` 原先的狀態、動作、排除項目與敏感度。若先前不存在，則只移除新覆寫項目，保留群組內所有其他項目。不要移除整個 DRS，也不要停用 WAF。 |
| 閘道回應重寫與關聯 | 只移除新增規則；若曾新增關聯或規則集，應先精確還原先前的 Basic、預設或個別路徑關聯，再移除已無參照的新規則集。保留其他重寫規則。 |

重新讀取變更的元件，重測登入、上傳、路由與 WAF 行為，並記錄恢復的功能及失去的防護。不要在未檢查同時或後續變更的情況下，直接還原整份原則或閘道。

## 資料平面驗證

### 擷取無害要求的對照測試結果

等待設定傳播完成後，只在已授權、非破壞性的預備環境端點測試。若需要驗證身分，請使用可拋棄的測試帳號與工作階段。不要向會執行業務交易的端點發送探測要求。請停用測試路由的快取；僅由用戶端送出 `Cache-Control` 標頭，不能保證 Front Door 不使用快取。不要為了測試而停用 WAF、加入繞過檢查的 Allow 規則，或將來源站開放給公網。

以下指令請以 Bash 執行，先將 `TEST_URL` 替換成**不含既有查詢字串**的 HTTPS URL。每次呼叫都會儲存回應標頭、本文、狀態與時間，不會跟隨重新導向，也不會重用回傳的 Cookie。重新導向不能證明最終 PHP 路由已經過檢查，應另外測試該路由。請限制證據目錄的存取，分享前遮蔽敏感標頭，並依組織政策保存與刪除資料。此處的 `curl` 刻意不使用 `--fail`，因為預期的 WAF 封鎖可能回傳 4xx；若發生傳輸錯誤，則應停止並調查。

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

請使用 URL 查詢標記、UTC 時間範圍、要求方法、用戶端位址，以及 Azure 回傳的追蹤或要求識別碼，關聯各項記錄。任意自訂的用戶端標頭不一定會出現在 WAF 記錄中；必要時，請設定預備環境來源站的存取記錄，保留該標記。要求端 Block 應有預期 WAF 規則與動作的記錄，且來源站不應出現對應要求。先用允許通過的對照要求確認來源站記錄完整；不完整的記錄中找不到要求，不足以作為證據。

### 要求驗收矩陣

請依主機、實際 PHP 路由與每一層 WAF 記錄各案例。允許通過的對照要求，應得到符合預期的應用程式回應，不一定是 HTTP 200。被其他無關的受控規則封鎖，不能算是待測自訂規則通過驗證。若未達到預期結果，應標記防護缺口並保留較強的圍堵措施；不要因為另一個要求被封鎖，就將失敗案例改稱成功。

| 案例 | 僅啟用基準規則 | 已啟用緊急 multipart 封鎖 |
| --- | --- | --- |
| 一般 GET 與淺層 URL 編碼表單 | 不應命中這三條規則；應用程式行為維持可用。 | 相同；另行設定的本文大小限制或受控規則仍可能生效。 |
| 一般 multipart 與無害空檔案 | 原則上不應命中基準規則；請驗證合法上傳行為。 | `EmergencyBlockPhpMultipart` 應在要求到達 PHP 前封鎖。 |
| 預設進度標記只出現在欄位名稱，欄位值為一般文字 | 必須由 `BlockPhpSessionUploadProgress` 執行 Block；若目標引擎的解析後 `PostArgs` 不涵蓋名稱，應記錄缺口。只匹配欄位值不能補足此缺口。 | 緊急 Block，不依賴欄位名稱解析。 |
| 標記只出現在欄位值 | 確認廣泛子字串匹配的行為與誤判；這不能證明進度欄位名稱案例也有效。 | 緊急 Block。 |
| 實際自訂的 `session.upload_progress.name` | 預設標記規則不保證涵蓋；必須另外審查防護範圍。 | 緊急 Block。 |
| URL 編碼表單巢狀 19 層與 20 層 | 19 層不應命中巢狀規則；20 層應由 `PhpFormNesting20` 記錄 Log，而不是 Block。 | 相同，因為此要求不是 multipart。 |
| 不含進度標記的 multipart，巢狀 19 層與 20 層 | 19 層不應命中巢狀規則；若平台能依設定解析並匹配名稱，20 層應由 `PhpMultipartNesting20` 記錄 Log。引擎差異造成的缺口應記錄。 | 兩種深度都由緊急規則封鎖，因此會遮蔽巢狀規則的驗證結果。 |
| Content-Type 大小寫變化與合法 boundary 參數 | 確認平台實際的正規化行為；不要假設 `BeginsWith` 與 `Contains` 的語意完全相同。 | 對平台接受的 multipart 變化格式執行緊急 Block。 |
| 在核准的預備環境安全範圍內，將標記放在本文檢查邊界附近或之外 | 記錄實際檢查與解析涵蓋範圍；不能宣稱保護整個本文。 | 依標頭判斷的 Block 不應受標記位置影響。 |
| 在核准範圍內，分別測試略低於與略高於非檔案及檔案大小上限的要求 | Application Gateway 必須證明設定的限制層會在 PHP 前拒絕超限要求；也要納入文件所述的上傳緩衝範圍。 | multipart 封鎖可能遮蔽大小限制結果；請使用隔離的原則另外驗證大小限制。 |
| 平台支援時，小型且有效的 HTTP/1.1 chunked multipart 與 HTTP/2 multipart | 觀察從邊緣到來源站的正規化行為；只比對可見的 `Transfer-Encoding` 不構成完整控制。絕不可組合互相衝突的訊息分框標頭。 | 必須在 PHP 前拒絕 multipart，或由可辨識的更嚴格邊緣控制拒絕；請正確歸因。 |
| 不含副檔名、不使用工作階段的 PHP 路由，以及其他網域 | 防護涵蓋要求應與具名上傳路由相同。 | 整個受影響 PHP 範圍都應套用相同的緊急 Block。 |

本驗收測試不得使用大量記憶體配置、過多 part 或標頭、序列化物件、可執行檔名、堆積噴灑，或觸發跨要求殘留狀態的手法。只使用小型且有明確上限的對照測試；若出現非預期延遲、5xx、工作處理程序重新啟動或資源壓力，應立即停止。大小與檢查邊界測試必須事先約定預備環境的記憶體預算及停止門檻。不要只為碰到測試邊界就調高限制。若另獲授權進行破壞性 PoC 評估，應使用可拋棄的隔離實驗環境，且不得連接正式環境或使用正式資料。

若 Front Door 位於 Application Gateway 前方，外層 Block 可能遮蔽內層缺少防護的問題。請透過核准的私有預備環境路徑，或隔離的等效拓撲，分別測試每一層，不要削弱正式環境的來源站存取限制。也要驗證兩層串接後的路徑，並分別記錄各層原則或資源 ID 及結果。

### 回應差異驗證矩陣

請使用隔離且限制存取的預備環境測試端點，只輸出**固定且無害**的回應標頭與固定本文，不啟動 PHP 工作階段、不接受任意標頭值，也不揭露機密。由負責人提供的靜態測試端點已足以驗證重寫規則，不要公開有漏洞的 PHP 頁面。來源站對照資料應從授權網路內取得，或使用受控測試端點的輸出，不要為此開放公網直接存取來源站。請停用路由快取，並在驗證後移除測試端點。

針對前述 Application Gateway 運算式，請將下列 Cookie 值各自作為獨立的 `Set-Cookie` 標頭測試。它們不包含漏洞利用內容或洩漏的記憶體資料：

| 來源站回應標頭值 | 公布運算式的預期結果 |
| --- | --- |
| `PHPSESSID=abc-123; Path=/; HttpOnly; Secure; SameSite=Lax` | 完整保留，包含所有屬性。 |
| `PHPSESSID=abc%2C123; Path=/` 與 `PHPSESSID=abc%2c123; Path=/` | 保留；運算式明確允許編碼後的逗號。 |
| `PHPSESSID=abc!fixture123; Path=/; HttpOnly` | 應匹配運算式，移除這個完整標頭。 |
| `PHPSESSID=abc%41fixture123; Path=/` | 應匹配並移除；此案例也說明它不是通用的 URL 解碼驗證器。 |
| `OTHER=keep; Path=/; Secure` 與應匹配的 PHP Cookie 同時存在 | 原樣保留 `OTHER`，只刪除匹配的 PHP 標頭。另以反轉標頭順序及多個 PHP Cookie 重測。 |
| 沒有 `Set-Cookie`，或只有不匹配的 Cookie | 回應維持不變。 |
| `phpSessid=abc!fixture123; Path=/` 或實際自訂的 Cookie 名稱 | 預設且區分大小寫的名稱不涵蓋此案例；必須另外審查，不能直接判定通過。 |
| `PHPSESSID=abc!;`，或結尾沒有分號的 `PHPSESSID=abc!fixture123` | 不匹配公布的運算式；請記錄此啟發式規則的涵蓋限制，不要宣稱所有格式異常的工作階段 Cookie 都會被移除。 |

請使用與要求對照測試相同的證據擷取選項，透過待測 WAF 路徑存取測試端點。逐一比對原始的 `Set-Cookie` 行，確認本文、狀態及其他標頭未改變，並確認來源站可達性符合預期。不要用逗號合併 Cookie，因為 `Expires` 屬性本身可能包含逗號。請使用可拋棄帳號，測試正常登入與登出、工作階段延續、重新導向、Cookie 屬性及閘道工作階段親和性 Cookie。

這些測試預期用來驗證 **Application Gateway 重寫匹配**，不是 Front Door 未公開的受控特徵。對 `99006001`，應先確認可用性、啟用狀態、支援的 DRS 與動作，以及設定傳播，再使用 Microsoft 核准的無害回應案例或由支援人員協助驗證。比對授權取得的對照回應與經防護回應；不要為取得應命中的樣本而啟用危險 PoC。若沒有已知會命中受控規則的樣本，請記錄為**設定已驗證；回應防護效果尚未驗證**。`99006001` 預期不會產生 WAF 記錄或命中次數證據；Application Gateway 重寫也不是要求端 WAF 規則命中。

### 證據與上線條件

- 保存原則與閘道 ID、SKU、引擎及規則集版本、UTC 測試時間範圍、來源修訂版本、核准變更、前後快照、路由關聯、探測標記，以及已遮蔽敏感內容的回應擷取資料。
- 要求端控制應保留 WAF 規則與動作、存取記錄關聯及來源站證據；回應端控制應保留標頭與本文差異證據。不要將一般存取記錄當成回應標頭擷取資料。
- 檢查來源站 PHP、FPM 或 Apache 錯誤記錄，尋找記憶體耗盡、工作階段銷毀失敗、工作處理程序當機或重新啟動，以及原因不明的 5xx。這些是需要調查的訊號，本身不能證明遭到漏洞利用。一般存取記錄通常不含 multipart 本文，因此搜尋進度標記並不是可靠的排除攻擊方式。
- 驗證來源站直接存取、替代入口與容錯移轉路徑的限制，以及預期的健康狀態探查、登入與上傳相容性，並獨立測試內外層 WAF 路徑。不要只為通過回歸測試就放寬排除條件或加入較早執行的 Allow 規則。
- 在預備環境演練各元件的復原，再重跑對照測試。同時記錄恢復的功能與失去的防護。在 PHP 修補或執行環境緩解措施尚未驗證，且沒有經核准的替代方案前，不要撤除正式環境的圍堵措施。

只有在要求端證據已審查、有有效測試案例的回應行為已驗證、回歸測試結果可接受、復原已演練，且 PHP 修補已有明確負責人與期限後，才能推進正式上線。不可用的規則或尚未驗證的受控回應防護效果，應明列為剩餘風險；控制平面的 `Succeeded`、本機正規表示式測試或 PoC 掃描器判定，都不是能抵抗漏洞利用的證明。

本文指令尚未對實際 Azure 原則執行部署。本機語法檢查不能驗證服務是否接受設定、設定傳播、匹配語意或抵抗漏洞利用的能力。

## 漏洞詳細說明與修補

| 漏洞 | 相關行為 | 採用 WAF 控制後仍存在的風險 |
| --- | --- | --- |
| CVE-2026-109618 | 記憶體不足的處理流程留下部分初始化的要求狀態，在清理時不安全。 | 小型要求、multipart 展開及應用程式特有的記憶體配置，仍可能耗盡記憶體。WAF 大小與巢狀層數限制不能證明記憶體安全。 |
| CVE-2026-109619 | 原本屬於某次要求的狀態，殘留到同一工作處理程序處理的後續要求。 | 上傳進度只是其中一個入口；標記封鎖或 multipart 封鎖不涵蓋其他產生及使用殘留狀態的路徑。 |
| CVE-2026-115560 | 已啟用上傳進度、初始序列化處理器為 `php_binary` 或 `php_serialize`，且應用程式在 `session_start()` 前將它切換成 `php`。 | WAF 無法確認這些伺服器端前提。不要自行設計針對 `ini_set`、`php_serialize` 或序列化語法的要求特徵；要求中不一定會出現這些字串。 |

**修補狀態：** PHP 8.2.35、8.3.36、8.4.27 及 8.5.12 包含 CVE-2026-109618 與 CVE-2026-109619 的修補。請使用這些版本、更新且仍受支援的修補版本，或已確認的供應商回補修正。不要假設這些版本也修補了 CVE-2026-115560；10 月 23 日公告指出，完整安全公告將隨下一次例行錯誤修正版本發布。請更新所有提供服務的執行環境，並重新建構、部署受影響的映像；更新主機不會更新容器內的 PHP。

若您無法管理 PHP 設定，請交由執行環境負責人處理。對 CVE-2026-109618，PHP 文件將由管理端強制設定 `memory_limit=-1`，搭配保守的 `post_max_size` 與資源隔離，列為部分緩解措施。移除 PHP 記憶體上限會增加可用性風險，必須先評估容量。底層記憶體配置仍可能失敗；不要以 `RLIMIT_AS` 或 `RLIMIT_DATA` 替代。WAF 限制不等同於這些執行環境變更。

針對上傳進度相關路徑及 CVE-2026-115560，請要求負責人在**要求解析前**停用 `session.upload_progress.enabled`，並重新啟動所有工作處理程序。不要依賴應用程式中的 `ini_set()` 或 FPM 的 `.user.ini`。對 PHP 8.5 上的 CVE-2026-109619，停用 `fatal_error_backtraces` 可移除另一條已確認路徑。也應修正早期設定診斷問題，以及攻擊者可觸發的嚴重錯誤或逾時。這些步驟不能取代用來修補非上傳殘留狀態問題的 PHP 更新。

回應內容清理無法防止 PHP 內部狀態損毀，也不能撤銷來源站已發生的程式碼執行。Application Gateway for Containers 是另一項產品：引用的指南只提供要求端自訂規則，不支援正規表示式回應重寫；受控回應規則則公告將於後續提供。不要將 v2 的重寫指令或 Front Door 規則 ID 套用到此產品。

## 來源解讀與防護範圍

[Microsoft 升級與 Azure WAF 指南](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623) 要求同時採用**要求端與回應端控制**，不只是三條自訂規則。10 月 22 日修訂版提供了前述 Cookie 重寫運算式。受影響設定與修補方式仍應以 PHP 官方公告為準。

第三方 [ikow/php2shell-poc 儲存庫](https://github.com/ikow/php2shell-poc/tree/31519e6d8a84dee1df1262961ed1bebb65accadd) 僅作為測試設計參考，固定使用提交版本 `31519e6d8a84dee1df1262961ed1bebb65accadd`。其中的攻擊鏈名稱、可靠性宣稱及掃描結果屬於研究觀察，不是 Azure 的防護保證，也不能與 CVE 一對一對應。其序列化處理器不一致的攻擊鏈，不能證明符合 CVE-2026-115560 所要求的精確執行期間切換條件。不要直接將其 ModSecurity 規則複製到 Azure 原則。

| 來源觀察 | 操作上的意義 | WAF 測試通過仍無法證明的事項 |
| --- | --- | --- |
| 攻擊鏈 A、C 使用上傳進度，且需要其他應用程式或設定條件。 | 測試預設及實際設定的進度欄位名稱，並納入帶檔名的 multipart 表單項目。 | 封鎖某個標記，不代表所有注入或反序列化路徑都已封閉。 |
| 攻擊鏈 B 需要攻擊者可控制的反序列化操作。 | 將修補及應用程式審查，與上傳控制分開處理。 | multipart 封鎖不能保護應用程式中任意的 `unserialize()` 呼叫。 |
| 攻擊鏈 D 涉及 mod_php 要求啟動階段的記憶體不足。 | 在不造成記憶體不足的前提下測試大小限制及支援的訊息分框；不要只保護具名上傳路由。 | 小型要求被接受或大型要求被拒絕，都不能證明記憶體安全。 |
| 攻擊鏈 E 描述依賴工作階段的狀態產生路徑，後續由另一個 PHP 端點的早期流程使用該狀態。 | 涵蓋所有受影響 PHP 路由，包括不含副檔名及不使用工作階段的端點；另行關聯工作處理程序失敗事件。 | 單一要求測試無法重現或排除跨要求的工作處理程序狀態利用。 |
| 偵測範例檢查檔名、回應錯誤及 chunked 訊息分框。 | 使用 Azure 支援的匹配變數、來源站遙測與安全測試資料；確認 Proxy 正規化後的訊息分框。 | 看不到 `Transfer-Encoding` 標頭或錯誤字串，不代表安全。 |

不要在正式環境執行該儲存庫的 exploit 或漏洞掃描器。有些檢查會刻意耗盡記憶體、損毀工作階段狀態或使工作處理程序當機。502、逾時或工作處理程序重新啟動，是需要調查的可用性事件，不能當成遠端程式碼執行或緩解成功的證據。

## 儲存庫工具

### 選用的腳本操作方式

前述 Azure CLI 步驟是主要流程。儲存庫腳本是部署相同基準規則的替代方式，不是額外必做步驟；不要同時執行兩種流程，重複安裝基準。腳本預設只預覽，會合併並保留其他規則、偵測優先序及較早執行的 Allow 問題，並支援備份、套用與復原流程。使用前請閱讀各平台文件。

只執行您平台的指令。`--backup-only` 會讀取 Azure 並儲存限制存取權限的本機備份；不帶動作旗標時只預覽；`--apply` 則是經審查與核准後，才可選擇執行的 **Azure 寫入操作**。

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

腳本的還原功能**只涵蓋自訂要求規則**，不包含原則大小設定、受控規則覆寫，或閘道重寫規則集及其關聯。這些變更仍須保留獨立的 CLI 快照與元件復原計畫。腳本備份有自己的格式，不要將前述原始 CLI 快照直接傳給腳本的復原操作。

- [Application Gateway WAF 工具與操作保護措施](azureapplicationgateway-waf/README.md)
- [Front Door WAF 工具與操作保護措施](azurefrontdoor-waf/README.md)
- [威脅獵捕查詢](threat-hunting/README.md)

## 官方參考資料

- [PHP 安全公告與 10 月 23 日公布的序列化處理器前提條件](https://www.php.net/archive/2026.php)
- [CVE-2026-109618：記憶體不足造成狀態損毀，進而導致遠端程式碼執行](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619：殘留的全域狀態導致遠端程式碼執行](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Microsoft PHP2Shell WAF 基準規則與限制](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684)
- [Microsoft 升級指南、回應規則推出時程與 Cookie 重寫](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623)
- [Application Gateway 自訂規則 CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy/custom-rule?view=azure-cli-latest)
- [Application Gateway 原則設定 CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy/policy-setting?view=azure-cli-latest)
- [Application Gateway 要求與上傳限制](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits)
- [Application Gateway 重寫行為、多個 Set-Cookie 的選擇方式與正規表示式限制](https://learn.microsoft.com/en-us/azure/application-gateway/rewrite-http-headers-url)
- [Application Gateway 重寫規則 CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/rewrite-rule?view=azure-cli-latest)
- [Application Gateway 重寫 ARM 結構與 headerValueMatcher](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2025-01-01/applicationgateways)
- [Application Gateway 路由規則關聯 CLI](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/rule?view=azure-cli-latest)
- [Front Door 自訂規則 CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/rule?view=azure-cli-latest)
- [Front Door 原則更新與 custom-rules JSON 輸入](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy?view=azure-cli-latest#az-network-front-door-waf-policy-update)
- [Application Gateway 原則更新與 custom-rules JSON 輸入](https://learn.microsoft.com/en-us/cli/azure/network/application-gateway/waf-policy?view=azure-cli-latest#az-network-application-gateway-waf-policy-update)
- [Front Door 可用受控規則定義 CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/managed-rule-definition?view=azure-cli-latest)
- [Front Door 受控規則覆寫 CLI](https://learn.microsoft.com/en-us/cli/azure/network/front-door/waf-policy/managed-rules/override?view=azure-cli-latest)
- [Front Door DRS、異常評分與 SKU 支援範圍](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs)
- [Front Door 檢查邊界比較](https://learn.microsoft.com/en-us/azure/frontdoor/high-availability#scenario-1-traffic-manager-failover-from-azure-front-door-to-an-application-gateway-waf)

## 第三方研究參考資料

- [已檢閱版本的 ikow PoC README](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/README.md)
- [ikow 攻擊鏈分析、前提條件與跨要求觀察](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/docs/ANALYSIS.md)
- [ikow ModSecurity 偵測指標，並非可直接匯入 Azure 的規則集](https://github.com/ikow/php2shell-poc/blob/31519e6d8a84dee1df1262961ed1bebb65accadd/detection/modsecurity.conf)