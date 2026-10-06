# Local validation record

Validated 6 October 2026. **137 offline checks passed; no failures.** All four production PowerShell files parsed successfully.

| Suite | Passed | Evidence |
|---|---:|---|
| Common helpers and static guards | 48 | Data-type preservation; hostile URI/next-link rejection; bounded pagination; partial/error handling; summaries/symbols; local export protection; all production scripts parsed and scanned |
| Entra identity collector | 34 | Complete workflow with a temporary fake Graph module; tenant/session binding; missing/malformed data; licence and dynamic-rule failures; baselines; separate User/Group SOA scope gates; **166 simulated GET requests** |
| Exchange collector | 13 | Complete workflow with a temporary fake Exchange module; tenant binding; localized calendar; full RoomList membership; order-independent baseline comparisons; lost room membership; unreadable permissions/members; export guards |
| AD/Connect collector | 42 | Production helper functions; version/support freshness; exact LDAP escaping; scheduler types; multi-value AD properties; module fallback/errors; mutation scan; real non-Windows run correctly stops with Unknown |

Runtime: portable official PowerShell **7.6.6**, macOS ARM64. The downloaded release asset was SHA-256 verified against the official PowerShell GitHub release digest. No system runtime or Microsoft modules were installed. Tests used temporary local stubs/fake modules and fresh processes, with authentication sentinels for cloud collectors. No live Graph, Exchange, AD, Connect or room-device calls were made.

The package targets PowerShell 7.2+, but execution was tested on 7.6.6 rather than every supported version. Actual Windows ActiveDirectory/ADSync compatibility, real Microsoft-module behaviour, operator permissions, tenant values, sync completion and device health remain unverified. The AD suite tests the actual non-Windows guard and isolated production functions; it is not an end-to-end Windows execution.

The static guards check for the targeted AD/Graph/Exchange/sync/service mutations, automatic module installation, direct Graph bypasses and non-GET/body requests. They are supplemented by workflow fixtures; they do not constitute a security certification or service-side dry run.

Material issues found and corrected during validation:

- Empty/missing user IDs, incomplete group classifications and missing dynamic rules cannot appear ready.
- Malformed scalar collection values, null entries, pagination caps, repeated or foreign next links leave evidence incomplete.
- Missing data differs from an explicit false/null/empty array; multi-member AD arrays remain complete and flat.
- A string `"True"` does not pass a Boolean synchronization check.
- SOA `false` is reported without claiming that it alone proves AD authority.
- Lost RoomList membership is detected by re-reading the original list after the change.
- Baselines cannot be replaced through the collectors' export option, even with `-ForceExport`; After snapshots cannot masquerade as Before baselines.

The ZIP is checked for readable entries and compared byte-for-byte with the source files. `manifest.sha256` lists the SHA-256 of every packaged file except itself. It is an integrity aid, not a signed publisher certificate.
