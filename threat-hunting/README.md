# PHP 漏洞威脅獵捕

依據 [NICS 2026-10-22 公告](https://www.nics.nat.gov.tw/core_business/information_security_information_sharing/Vulnerability_Alert_Announcements/5c4e9af1-4275-44ef-a277-c692786b5a2c/)，追查 CVE-2026-109618 與 CVE-2026-109619 相關暴露面及可疑活動。公告描述未經身分鑑別的攻擊者可透過特製 multipart/form-data HTTP 請求觸發 PHP 使用釋放後記憶體漏洞，導致任意程式碼執行，且已有 PoC。

## 執行順序

適用於 **Microsoft Defender XDR 的進階搜捕**，需已部署 Microsoft Defender for Endpoint 並有對應資料表與裝置遙測。這些不是可直接套用到任意 Sentinel 工作區的通用查詢。

1. 執行 [windows.kql](windows.kql)，取得 Windows PHP 程序、檔案活動與 DLL 載入跡象，以及可取得的程序版本。結果依裝置、PHP 路徑與觀察到的版本分組，保留並存版本及未知版本，不以最新一筆事件取代全部版本。
2. 執行 [linux.kql](linux.kql)，盤點 Linux PHP 程序與其引發的檔案／程序活動。涵蓋 `php`、`php8.3`、`php-fpm`、`php-fpm8.3`、`php8.3-fpm`、`php-cgi` 及 FPM 程序標題等命名形式。名稱中的 `8.3` 不是完整修補版本。
3. 在 [machine.kql](machine.kql) 將 `TargetDeviceName` 改成盤點結果的完整 `DeviceName`，執行單機事件時間軸。必要時先依環境改用唯一的 `DeviceId` 篩選，避免裝置重新註冊或同名裝置混淆。
4. 優先檢視 `Triage` 標示的 shell／工具與腳本／可執行檔活動，再以時間、程序路徑、`InitiatingProcessId` 及 `InitiatingProcessCreationTime` 關聯事件。PID 可能重複使用，不應只依 PID 關聯。

每個檔案是一份可獨立執行的查詢。預設回溯 30 天，可調整 `Lookback`，但受租用戶保留期限制。單機查詢只回傳最新 1,000 筆；事件多時請縮小時間範圍並分段調查，以免舊事件被截斷。這些是調查用查詢，不是已調校完成的自訂偵測規則。

## 版本判讀

以下門檻僅依上述公告，不代表已獨立驗證 PHP 上游修補發布狀態：

| 分支 | 公告列出的受影響版本 | 公告建議安全版本 |
| --- | --- | --- |
| 5.4–5.6、7.0–7.4、8.0–8.1 | 所有版本，已 EOL | 遷移至受支援的安全版本 |
| 8.2 | 8.2.34（含）以下 | 8.2.35 |
| 8.3 | 8.3.35（含）以下 | 8.3.36 |
| 8.4 | 8.4.26（含）以下 | 8.4.27 |
| 8.5 | 8.5.11（含）以下 | 8.5.12 |

Windows 查詢使用數值版本比較，而非字串排序。僅接受完整三段穩定版本或四段數字檔案版本；空值、預發布版本與帶後綴版本列為未知，避免擅自剝除後綴後判定安全。版本判讀只是分流，檔案版本 Metadata 可能不完整或遭竄改。

DLL 載入事件提供的是載入者版本，而非 DLL 版本，因此不拿 Apache／IIS 的版本當成 PHP 版本。Linux 通常沒有可用的 PE 版本 Metadata，請用套件管理器、發行版安全公告與實際服務設定確認。發行版可能回補修補而保留舊版本號；CLI 與網站使用的 FPM／CGI／Apache PHP 模組也可能來自不同安裝路徑。更新後還需確認服務已重新啟動並使用修補版本。

## 證據限制

- PHP 檔案活動不代表已安裝或正在提供服務；刪除或更新事件也可能命中。請檢視 `ActionType` 與實際服務設定。沒有事件不代表沒有 PHP，長時間執行、未接入 MDE 的主機、容器或 Apache 內嵌模組可能未被盤點。
- 單機查詢納入 Apache、IIS、Nginx 活動以協助調查內嵌 PHP，但 Web 活動本身不能證明使用 PHP。Linux Apache 內嵌模組不在 Linux PHP 程序盤點的涵蓋範圍。
- PHP／Web 啟動 shell、下載工具或寫入腳本，也可能是合法應用行為；需比對應用基線、帳號、路徑、雜湊與同時間 HTTP 記錄。攻擊也可能只在程序記憶體內執行，不產生子程序或落地檔案。不能將查詢命中直接歸因於這兩個 CVE。
- `DeviceNetworkEvents` 不提供完整 HTTP 標頭或 multipart 請求本文，也包含非對外連線事件。請搭配反向代理、WAF 與 Web 存取／錯誤記錄，關聯來源 IP、URI、上傳時間與 PHP 崩潰。正常 multipart 上傳不等於攻擊，公告也未提供可直接套用的特定惡意 IP、雜湊或請求特徵。
- 本地只能檢查查詢內容與編輯器診斷；必須在實際 Defender 租用戶中確認資料表可用性、欄位、查詢限制及結果。請勿把零筆結果當成排除漏洞或入侵的證據。

## 欄位參考

- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceImageLoadEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table)
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [parse_version()](https://learn.microsoft.com/en-us/kusto/query/parse-version-function)