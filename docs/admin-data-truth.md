# Admin Data Truth Inventory

This inventory records the source and honest fallback for every HIP admin page.
Operational counts come from authorized application services. A zero means an
available source returned no matching records; an em dash means the source is
unavailable or not connected. Dashboard snapshots expose their generation time,
primary source, and optional dependency availability.

| Page | Source of truth | Empty or unavailable behavior |
| --- | --- | --- |
| `AdminAlerts.razor` | `IAdminDashboardService` privacy-safe threat projection | Explicit empty/filter states; refresh failures retain rows and show an error. |
| `AdminApiDeveloper.razor` | Authorized service-client management endpoints | Explicit empty list; secrets are returned only once at creation. |
| `AdminAppeals.razor` | Async `IAppealService` reads and actor-authorized decisions | Explicit loading/empty/not-found/error states; decisions require an operator reason, persist asynchronously, and write privacy-safe audit evidence. Sample creation is development-only and labelled. |
| `AdminAuditLogs.razor` | `IAuditLogService` | Explicit empty/filter states; refresh failures retain rows and show an error. |
| `AdminDashboard.razor` | `IAdminDashboardService` | Shows snapshot time/source; unavailable metrics use an em dash and dependency health degrades. |
| `AdminDomainCertificates.razor` | `IDomainCertificateAdminQuery` plus policy-authorized application and lifecycle services | Explicit loading/empty/error states; approval, security review, issuance, suspension, reinstatement, and revocation remain separate persisted operations. Domain control and signatures are not presented as automatic safety claims. |
| `AdminFeedbackLoop.razor` | Bounded `IAdminFeedbackService` projection over durable weighted-feedback records | Explicit loading/empty/not-found/error states; shows per-domain counts, current 14-day weighted interpretation, and a privacy-safe event timeline. Reporter/page hashes and raw content are excluded. |
| `AdminLicenseDetail.razor` | `ISetupCodeLicenseService` | Not-found state; mutations remain policy- and step-up-authorized. |
| `AdminLicenseNew.razor` | `ISetupCodeLicenseService` | No code before creation; creation remains policy- and step-up-authorized. |
| `AdminLicenses.razor` | `ISetupCodeLicenseService` | Explicit empty list; all totals derive from the same returned collection. |
| `AdminMessageShield.razor` | Dashboard scan/review projection | Message ingestion is explicitly unavailable; no message count or rows are invented. |
| `AdminPlatformConnections.razor` | `IPlatformConnectionService` plus dashboard evidence | Browser state means evidence received, not proven connectivity; unconfigured connectors are labelled. |
| `AdminPrivacySafety.razor` | Static product boundary documentation | Makes future desktop-only capabilities explicit; contains no operational counts. |
| `AdminReportsPage.razor` | Single dashboard snapshot | Shows generation time/source; empty is zero and unavailable is an em dash. |
| `AdminReputationOverrides.razor` | `IReputationOverrideService` | Empty queue; sample creation is development-only and labelled. |
| `AdminReputationOverview.razor` | Dashboard reputation projection | Explicit no-data state; no generated reputation records. |
| `AdminReputationSignals.razor` | Single dashboard snapshot | Empty activity is explicit; unavailable source metrics use an em dash. |
| `AdminReview.razor` | `IReviewQueueService` | Empty queue; sample creation is development-only and labelled. |
| `AdminReviewSignals.razor` | `IAdminReviewQueueService` | Explicit empty queue; no generated sample signals. |
| `AdminRoles.razor` | Static current policy reference | Describes the implemented policy map; it is not a role-management claim. |
| `AdminRules.razor` | Rule repositories and admin rule services | Empty rule lists are explicit; privacy-safe simulation is labelled and never presented as live. |
| `AdminScanDetails.razor` | `IAdminScanDetailService` | Explicit missing-scan state; read-only limitations are stated. |
| `AdminSecondLifeHudSimulator.razor` | `ISecondLifeHudSimulationService` | Clearly labelled development simulator with intentional sample inputs. |
| `AdminSelfHealing.razor` | `ISelfHealingAnalysisService` | Clearly labelled development analysis with intentional privacy-safe sample findings. |
| `AdminSenderProfiles.razor` | `IAdminSenderProfileService` over durable reputation profiles and events | Explicit empty/error states; only stored Sender profiles are listed, with bounded privacy-safe reasons and event history. |
| `AdminSettings.razor` | Current-process external-provider options | Save text says the update is process-local and must be persisted through configuration/secrets. |
| `AdminTourScan.razor` | Static product tour | Clearly titled sample threat and never linked as live scan evidence. |
| `AdminWebsiteIdentity.razor` | `IWebsiteIdentityService` | Explicit empty/search/not-found states; privileged mutations reauthorize the actor. |

Intentional simulations and development-only seed actions are allowed only when
they are visibly labelled and cannot be confused with operational data. This
inventory does not authorize production sample generation.
