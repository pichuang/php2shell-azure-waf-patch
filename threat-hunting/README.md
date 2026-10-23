# PHP Vulnerability Threat Hunting

Investigate exposure and suspicious activity related to CVE-2026-109618 and CVE-2026-109619 based on the [NICS advisory dated 2026-10-22](https://www.nics.nat.gov.tw/core_business/information_security_information_sharing/Vulnerability_Alert_Announcements/5c4e9af1-4275-44ef-a277-c692786b5a2c/). The advisory describes PHP use-after-free vulnerabilities that unauthenticated attackers can trigger through specially crafted multipart/form-data HTTP requests, resulting in arbitrary code execution. A proof of concept (PoC) is already available.

## Execution Order

These queries are intended for **advanced hunting in Microsoft Defender XDR** and require Microsoft Defender for Endpoint deployment, the corresponding tables, and device telemetry. They are not generic queries that can be applied directly to any Sentinel workspace.

1. Run [windows.kql](windows.kql) to identify Windows PHP processes, file activity, and DLL loads, along with process versions where available. Results are grouped by device, PHP path, and observed version, preserving coexisting and unknown versions instead of replacing all versions with the latest event.
2. Run [linux.kql](linux.kql) to inventory Linux PHP processes and the file/process activity they initiate. Covered naming patterns include `php`, `php8.3`, `php-fpm`, `php-fpm8.3`, `php8.3-fpm`, `php-cgi`, and FPM process titles. The `8.3` in a name is not a complete patch version.
3. In [machine.kql](machine.kql), replace `TargetDeviceName` with the full `DeviceName` from the inventory results, then run the single-device event timeline. If necessary, adapt the query to filter by a unique `DeviceId` first to avoid confusion caused by device re-registration or devices with identical names.
4. Prioritize shell/tool and script/executable activity flagged by `Triage`, then correlate events using the time, process path, `InitiatingProcessId`, and `InitiatingProcessCreationTime`. PIDs can be reused; do not correlate events by PID alone.

Each file contains a standalone query. The default lookback is 30 days; adjust `Lookback` as needed, subject to your tenant's retention period. The single-device query returns only the latest 1,000 events. For high event volumes, narrow the time range and investigate in separate intervals to avoid truncating older events. These are investigation queries, not fully tuned custom detection rules.

## Version Interpretation

The following thresholds are based solely on the advisory above and do not imply independent verification of upstream PHP patch release status:

| Branch | Affected Versions Listed in the Advisory | Safe Version Recommended by the Advisory |
| --- | --- | --- |
| 5.4-5.6, 7.0-7.4, 8.0-8.1 | All versions; end of life (EOL) | Migrate to a supported, safe version |
| 8.2 | 8.2.34 and earlier | 8.2.35 |
| 8.3 | 8.3.35 and earlier | 8.3.36 |
| 8.4 | 8.4.26 and earlier | 8.4.27 |
| 8.5 | 8.5.11 and earlier | 8.5.12 |

The Windows query compares versions numerically rather than sorting strings. It accepts only complete three-component stable versions or four-component numeric file versions. Empty values, prerelease versions, and versions with suffixes are classified as unknown to avoid declaring a version safe after arbitrarily stripping its suffix. Version interpretation is only a triage aid; file version metadata may be incomplete or tampered with.

DLL load events provide the loader's version, not the DLL's version, so Apache/IIS versions are not treated as PHP versions. Linux typically lacks usable PE version metadata; verify versions using the package manager, distribution security advisories, and actual service configuration. Distributions may backport fixes while retaining older version numbers. The CLI and the FPM/CGI/Apache PHP modules serving websites may also use different installation paths. After updating, confirm that services have restarted and are using the patched version.

## Evidence Limitations

- PHP file activity does not prove that PHP is installed or serving requests; deletion or update events may also match. Review `ActionType` and the actual service configuration. An absence of events does not prove an absence of PHP. Long-running processes, hosts not onboarded to MDE, containers, or embedded Apache modules may be missed by the inventory.
- The single-device query includes Apache, IIS, and Nginx activity to help investigate embedded PHP, but web activity alone does not prove PHP usage. Embedded Apache modules on Linux are outside the scope of the Linux PHP process inventory.
- PHP/web processes launching shells or download tools, or writing scripts, may be legitimate application behavior. Compare findings against application baselines, accounts, paths, hashes, and HTTP logs from the same period. Attacks may also execute entirely in process memory without spawning child processes or writing files to disk. Query matches cannot be directly attributed to these two CVEs.
- `DeviceNetworkEvents` does not provide complete HTTP headers or multipart request bodies, and it also includes events other than outbound connections. Correlate source IPs, URIs, upload times, and PHP crashes with reverse proxy, WAF, and web access/error logs. Normal multipart uploads are not evidence of an attack. The advisory does not provide specific malicious IPs, hashes, or request signatures that can be applied directly.
- Local checks are limited to query content and editor diagnostics. Table availability, fields, query limits, and results must be verified in an actual Defender tenant. Do not treat zero results as evidence that rules out a vulnerability or compromise.

## Field References

- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceImageLoadEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table)
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [parse_version()](https://learn.microsoft.com/en-us/kusto/query/parse-version-function)