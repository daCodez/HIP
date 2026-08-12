# HIP.Contracts

`HIP.Contracts` contains dependency-free public data contracts that HIP can
share without exposing proprietary scoring, detection, entitlement, or
certificate-issuance logic.

This project is a licensing-boundary candidate. Its presence in the repository
does not grant a license or make it an independently published package. A
specific license and distribution mechanism must be approved before external
publication.

Public contracts may describe stored results and evidence already approved for
disclosure. Implementations that calculate scores, select providers, apply
private thresholds, or issue certificates must remain outside this assembly.

The plugin SDK surface is limited to privacy-safe manifests, runtime status,
feature metadata, and provider declaration interfaces. HIP retains control of
plugin discovery, validation, configuration, secrets, plan evaluation, billing,
provider selection, scoring, evidence collection, and certificate issuance.
