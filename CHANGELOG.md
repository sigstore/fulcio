# v1.8.3

## Vulnerability Fixes

* https://github.com/sigstore/fulcio/security/advisories/GHSA-f83f-xpx7-ffpw; prevents OOM condition due to malformed OIDC token (#2233)

## Features

* feat: Add support for skipping email_verified claim requirement per issuer (#2220)
* add meta-issuer circleci block (#2215)
* add circleci info to fulcio (#2192)

## Testing

* Add basic E2E tests (#2230)

# v1.8.2

## Testing

* make email address in test cases rfc822 conformant (#2205)

# v1.8.1

Same as v1.8.0, but with a fix for the CI build pipeline.

# v1.8.0

## Bug Fixes

* fix: K8s API does not accept unauthorized requests (#2111)
* fix: vault for enterprise expects only the key name (#2117)
* fix(config): respect cacert on oidc-issuers (#2098)
* Register `/healthz` endpoint when listening on duplex http/grpc port (#2046)

## Features

* feat: adds cert loading and key-match validation. (#2173)
* expose gcp kms retry and timeout options (#2132)
* server: Use warning log level for client errors (#2147)
* Add workflow to periodically validate OIDC issuers (#2188)
* Add Chainguard issuer (#2078)
* Add logging for template error (#2194)
* Add extension for deployment environment (#2190)

## Removal

* Remove cmd/create_tink_keyset (#2096)

# v1.7.1

v1.7.1 contains a bug fix for extensions for CI providers where the OIDC claims
include HTML escape characters. If a client attempted to verify an extension value,
verification would fail unless an HTML-escaped string was used in the comparison.
Extension values will no longer be escaped.

## Bug Fixes

* Do not HTML-escape extension values (#2023)

# v1.7.0

v1.7.0 includes a change to how proof of possession signatures are verified.
Fulcio has updated the expected hashing algorithm for ECDSA P-384 and P-521
signatures to be SHA-384 and SHA-512, in line with CSR signature verification.
Cosign is actively being updated to support this for when signing with a
managed key and requesting a certificate.

## Features

* Allow configurable client signing algorithms (#1938)
* Use different hash in proof of possession based on key (#1959)
* Tls verification on OIDC issuers (#1932)
* feat: adds cert-utility. (#1870)
* feat: makes leaf optional and other changes.  (#1931)

## Bug Fixes

* Remove err impossible condition: nil != nil (#1934)
* mark principal and issuer class under pkg/identity as deprecated (#1980)

## Contributors

* Carlos Tadeu Panato Junior
* Hayden B
* ian hundere
* Praful Khanduri
* Ramon Petgrave
* Riccardo Schirone
* Sujal Gupta

# v1.6.6

## Features

* Configure additional certificate extensions for Buildkite (#1903)
* Relax gomod (#1909)
* update builder to use go1.23.4 (#1883)
* config: Add IBM OIDC provider (#1892)
* Add Kaggle identity provider (#1850)

## Contributors

* Bob Callaway
* Carlos Tadeu Panato Junior
* Hayden B
* James Healy
* Stefan Berger
* Trishank Karthik Kuppusamy

# v1.6.5

## Features

* use go1.23.2 (#1834)
* fallback to json default cfg path if yaml does not exist (#1810)
* Include IDP type and subject domain in configuration API response (#1824)

## Documentation

* Update OIDC claim mapping table to reflect the current state (#1801)


## Contributors

* Aditya Sirish
* Bob Callaway
* Carlos Tadeu Panato Junior
* Hayden B
* Nina
* Richard Fan

# v1.6.4

## Features

* use go1.22.6 to build fulcio (#1793)

## Bugs

* Revert "If custom server url exists, use that instead of the default one." (#1791)

## Contributors

* Carlos Tadeu Panato Junior
* Fredrik Skogman

# v1.6.3

## Features

* If custom server url exists, use that instead of the default one. (#1776)

## Contributors

* Fredrik Skogman
* Javan Lacerda

# v1.6.2

## Bug Fixes

* fix: adding ci provider for meta-issuers (#1767)

## Contributors

* Javan Lacerda

# v1.6.1

## Bug Fixes

* fix: removing surplus slash, making logs richer (#1762)

## Contributors

* Javan Lacerda

# v1.6.0

v1.6.0 adds support for onboarding CI identity providers via configuration
rather than code changes, which should greatly simplify the onboarding process.

## Features

* CiProvider as a new OIDCIssuer type (#1729)
* Add TLS support for CTLog (#1718)
* Added support for email\_verified being a string or bool (#1744)

## Documentation

* Update IDP requirements (#1742)

## Public Good Instance Configuration

* Move codefresh and buildkite to ci-provider identity (#1743)
* Move gitlab to ci-provider (#1740)
* Migrate github to ci provider flow (#1738)
* add Hellō provider (#1739)
* Move configuration to yaml format (#1720)
* Removes identity providers federation (#1736)

## Contributors

* Andrew Block
* cpanato
* Dick Hardt
* Firas Ghanmi
* Hayden B
* Javan Lacerda
* Matt Moore

# v1.5.1

## Bug Fixes

* Surface the right `Name()` from our principal. (#1726)

## Contributors

* Matt Moore

# v1.5.0

## Features

* Add Chainguard OIDC provider. (#1703)
* Adding support for configuration from yaml file (#1687)
* Upgrade go to 1.22 (#1625)

## Documentation

* oid-info: fix table render (#1662)
* docs: Fix extensions for digest values requiring a type prefix (#1661)

## Contributors

* Bob Callaway
* Carlos Tadeu Panato Junior
* Facundo Tuesca
* Javan Lacerda
* Matt Moore
* Tomas Turek
* William Woodruff

# v1.4.5

## Features

* Add Codefresh OIDC provider (#1593)

## Contributors

* ilia-medvedev-codefresh

# v1.4.4

## Features

* Add production OIDC provider for Eclipse (#1472)
* Change parseExtension function to be public (#1584)
* Allow exposed metrics port to be overridden (#1518)
* add configurable idle timeout

## Bug Fixes

* Fix docker-compose service order (#1537)
* Fix debug docker-compose setup (#1529)
* Fix docker-compose file (#1560)

## Documentation

* Create new-idp-requirements.md (#1447)
* docs: Add back descriptive content on cert issuing (#1494)
* Added GitLab OIDC documentation to the /docs/oidc.md file that was missing. (#1574)

## Misc

* update builder to use go1.21.6
* Move kubernetes CA processing in config.prepare (#1454)
* Lots of dependabot updates

## Contributors

* Bob Callaway
* Carlos Tadeu Panato Junior
* Colleen Murphy
* Cyril Cordoui
* Hayden B
* John Kjell
* Paul Welch
* Tanner Jones

# v1.4.3

## Bug Fixes
* Bump golang.org/x/net from 0.15.0 to 0.17.0 in /hack/tools (#1409)
* Bump golang.org/x/net from 0.15.0 to 0.17.0 (#1410)

## Contributors
* dependabot

# v1.4.2

* move to go 1.21.3 to pick up fixes for CVE-2023-39325

## Bug Fixes
* update builder image to use go1.21.3 (#1407)
* Bump github.com/google/go-cmp from 0.5.9 to 0.6.0 (#1405)
* Bump google.golang.org/grpc from 1.58.2 to 1.58.3 (#1404)
* Bump golang from 1.21.2 to 1.21.3 (#1406)
* Bump go.step.sm/crypto from 0.35.1 to 0.36.0 (#1403)
* Bump google.golang.org/api from 0.145.0 to 0.146.0 (#1402)
* Bump sigs.k8s.io/release-utils from 0.7.4 to 0.7.5 (#1401)

## Contributors
* Carlos Tadeu Panato Junior

# v1.4.1

v1.4.1 disables CGO for released binaries and containers. If you need support
for an HSM-backed CA, compile Fulcio with CGO\_ENABLED=1.

The Distroless base image of the released containers has been updated to Debian 12,
`gcr.io/distroless/static-debian12:nonroot`.

## Features

* Do not block startup if OIDC provider cannot be created (#1389)
* Gracefully shutdown HTTP, gRPC, and Prom servers (#1342)
* Create interface for GRPC server which encompasses the GRPC HealthServer (#1334)

## Release

* update builder image to use go1.21.2 (#1397)
* Disable CGO on release builds (#1368)

## Contributors

* Appu
* Hayden B
* Jon Johnson
* Jussi Kukkonen
* Priya Wadhwa
* William Woodruff

# v1.4.0

## Features

* Add "Source Repository Visibility At Signing" ext (#1279)
* Expose SkipExpiryCheck OIDC Config Option in Verifier (#1271)

## Documentation

* Update loadtest instructions (#1284)

## Contributors

* Hayden B
* Philip Harrison
* Priya Wadhwa

# v1.3.4

## Features

* Update GitLab claim mappings for build configs (#1206)
* add container builds for each push to main (#1269)

## Bug fixes

* always use non-TLS credentials to connect over unix domain socket (#1268)

## Contributors

* Marshall Cottrell
* Bob Callaway

# v1.3.3

## Features

* add HTTP and GRPC health check endpoints (#1258)
* add fsnotify-backed cache for reading TLS PKI material (#1256)

## Contributors

* Bob Callaway
* Hayden B

# v1.3.2

## Features

* configure server-side TLS on grpc listener (#1252)

## Bug fixes

* gitlab: remove build config URI. (#1183)

## Documentation

* Update OID info (#1188)
* Fix spellings, update protoc (#1184)
* docs/oid-info: clarify source of issuer extensions (#1158)

## Contributors

* Billy Lynch
* Bob Callaway
* Carlos Tadeu Panato Junior
* Hayden B
* Kristian Klausen
* William Woodruff

# v1.3.1

## Bug Fixes

* fix cert.URIs for GitLab CI (#1144)

## Contributors

* Carlos Tadeu Panato Junior

# v1.3.0

Fulcio 1.3.0 adds support for GitLab CI.

## Enhancements

* Add GitLab.com OIDC to Fulcio (#983)
* Change ParseDerString to Public Function (#1119)
* Support enterprise-unique GitHub Actions OIDC issuer URLs (#1088)

## Documentation

* Map GitLab OIDC token claims to Fulcio OIDs (#1097)
* Mark GitLab JWT claim fields that are still WIP. (#1139)
* oidc.md: Add section for how to select SANs. (#1127)
* oid-info: Drop Build Signer Digest requirement from MUST -> SHOULD (#1126)
* update docs to use CDN-backed TUF endpoint (#1108)

## Contributors

* Alishan Ladhani
* Billy Lynch
* Bob Callaway
* Carlos Tadeu Panato Junior
* Hayden B
* James Ma
* Paul Welch
* Reed Loden
* Sandipan Panda

# v1.2.0

Fulcio 1.2.0 adds support for additional extensions in certificates issued for
CI platforms, starting with GitHub Actions.

Deprecation warning: OIDs `1.3.6.1.4.1.57264.1.1` through `1.3.6.1.4.1.57264.1.6` have been deprecated,
but are still present in the issued certificates. The new extensions `1.3.6.1.4.1.57264.1.8`
through `1.3.6.1.4.1.57264.1.21` are correctly formatted as DER-encoded strings.

## Enhancements

* Implement standardized CI extensions for GitHub (https://github.com/sigstore/fulcio/pull/1073)
* Allow specifying ChallengeClaim for an Issuer in the Fulcio config (https://github.com/sigstore/fulcio/pull/1007)
* Support custom OIDC issuers
    * Begin implementing Issuer interface for email and github identities (https://github.com/sigstore/fulcio/pull/1005)
    * Implement Issuer interface for spiffe and kubernetes types (https://github.com/sigstore/fulcio/pull/1033)
    * Implement Issuer interface for username and uri Issuer types (https://github.com/sigstore/fulcio/pull/1035)
    * implement Issuer interface for buildkite (https://github.com/sigstore/fulcio/pull/1037)
    * Create BaseIssuer type to implement Match for all Issuers (https://github.com/sigstore/fulcio/pull/1039)
    * Use Issuer interface to allow for custom issuers (https://github.com/sigstore/fulcio/pull/1008)

## Bug Fixes

* Don't add nil issuers to issuer pool (https://github.com/sigstore/fulcio/pull/1053)

## Documentation

* Standardizing Fulcio Certificate Extensions (https://github.com/sigstore/fulcio/pull/945)
* Add documentation for adding a new OIDC issuer (https://github.com/sigstore/fulcio/pull/1042)
* Update TUF instructions in README (https://github.com/sigstore/fulcio/pull/1079)

## Contributors

* Carlos Tadeu Panato Junior
* Hayden B
* Philip Harrison
* priyawadhwa

# v1.1.0

Fulcio 1.1.0 adds support for Buildkite, supports running the HTTP and gRPC servers on the same port,
and fixes a few bugs in the GCP CA Service integration. Fulcio 1.1.0 updates Go to 1.20.

## Enhancements

* Add Buildkite OIDC to Fulcio (https://github.com/sigstore/fulcio/pull/890)
* Update Fulcio to 1.20 (https://github.com/sigstore/fulcio/pull/989)
* Add in --duplex flag to run HTTP and GRPC servers on the same port (https://github.com/sigstore/fulcio/pull/931)
* Expose client options for google ca (https://github.com/sigstore/fulcio/pull/892)

## Bug Fixes

* googleca: close certificate authority client when done (https://github.com/sigstore/fulcio/pull/930)
* Fix bugs in googleca and update flag description (https://github.com/sigstore/fulcio/pull/897)
* Fix pkcs11ca with no cgo compilation bug (https://github.com/sigstore/fulcio/pull/898)

## Miscellaneous

* Add custom error logs when communicating with the CA backend (https://github.com/sigstore/fulcio/pull/966)
* Add new format for AKS OIDC issuer (https://github.com/sigstore/fulcio/pull/971)
* expose rpc options to add auth creds (https://github.com/sigstore/fulcio/pull/934)
* Refactor kmsca constructor to accept x509.Certificates (https://github.com/sigstore/fulcio/pull/917)

## Contributors

* Bob Callaway
* Carlos Tadeu Panato Junior
* Harry Marr
* Hayden B
* Hector Fernandez
* Luke Hinds
* priyawadhwa
* Samuel Cochran
* William Woodruff
* Yoriyasu Yano

# v1.0.0

1.0 release!

No changes from the previous release v1.0.0-rc.0.

# v1.0.0-rc.0

**Notice for Deprecation**: The legacy (V1) API will be deprecated by February
1, 2023, and no longer supported in the public instance. Please update clients
to the V2 API, which supports for gRPC and HTTP.

## Enhancements

* use same way to output version and expose build info to prometheus (#815)

## Documentation

* Update swagger doc version for Fulcio 1.0 (#816)

## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)

# v0.6.0

**Note**: Changed username identity format to username!Domain, username now specified in the OtherName SAN. If you have deployed your own instance of Fulcio and are using username issuers, you must update to the latest Cosign release.

## Enhancements

* Change username format, enforce identity format (https://github.com/sigstore/fulcio/pull/802)
* Export Fulcio extension OIDs (https://github.com/sigstore/fulcio/pull/761)

## Documentation

* Update how-certificate-issuing-works.md (https://github.com/sigstore/fulcio/pull/755)


### Bug Fixes

* Fix documentation link (https://github.com/sigstore/fulcio/pull/798)

## Miscellaneous

* upgrade to go1.19 (https://github.com/sigstore/fulcio/pull/767)


## Contributors

* Billy Lynch (@wlynch)
* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)

# v0.5.4

### Bug Fixes

* adding tuf root env variable (https://github.com/sigstore/fulcio/pull/751)

## Contributors

* Carlos Tadeu Panato Junior (@cpanato)

# v0.5.3

## Bug Fixes

* Clean up unix socket (https://github.com/sigstore/fulcio/pull/739)
* address Potential Slowloris Attack because ReadHeaderTimeout is not configured in the http.Server (https://github.com/sigstore/fulcio/pull/735)
* fix example to explicitly set port for gRPC call (https://github.com/sigstore/fulcio/pull/732)

## Documentation

* Create certificate specification (https://github.com/sigstore/fulcio/pull/703)
* Add documentation for SCT formats (https://github.com/sigstore/fulcio/pull/718)
* Update certificate issuance documentation (https://github.com/sigstore/fulcio/pull/702)

## Miscellaneous

* Bump actions/dependency-review-action from 2.0.4 to 2.1.0 (https://github.com/sigstore/fulcio/pull/744)
* Update scorecard-action to v2:alpha (https://github.com/sigstore/fulcio/pull/746)
* update builder and cosign images (https://github.com/sigstore/fulcio/pull/743)
* Bump google.golang.org/api from 0.92.0 to 0.93.0 (https://github.com/sigstore/fulcio/pull/741)
* Bump go.step.sm/crypto from 0.17.1 to 0.17.2 (https://github.com/sigstore/fulcio/pull/742)
* update github.com/google/tink/go to 1.7.0 and fix deprecation (https://github.com/sigstore/fulcio/pull/736)
* Bump go.step.sm/crypto from 0.17.0 to 0.17.1 (https://github.com/sigstore/fulcio/pull/737)
* Bump google.golang.org/api from 0.91.0 to 0.92.0 (https://github.com/sigstore/fulcio/pull/733)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/731)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/722)
* Bump go.uber.org/zap from 1.21.0 to 1.22.0 (https://github.com/sigstore/fulcio/pull/730)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.11.0 to 2.11.2 in /hack/tools (https://github.com/sigstore/fulcio/pull/726)
* install protobuff 3.20.1 (https://github.com/sigstore/fulcio/pull/728)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.11.1 to 2.11.2 (https://github.com/sigstore/fulcio/pull/724)
* Bump github.com/prometheus/client_golang from 1.12.2 to 1.13.0 (https://github.com/sigstore/fulcio/pull/725)
* Bump github/codeql-action from 2.1.17 to 2.1.18 (https://github.com/sigstore/fulcio/pull/721)
* Bump google.golang.org/api from 0.90.0 to 0.91.0 (https://github.com/sigstore/fulcio/pull/720)
* Bump golang from 1.18.4 to 1.18.5 (https://github.com/sigstore/fulcio/pull/717)
* Bump golang from `6e10f44` to `8a62670` (https://github.com/sigstore/fulcio/pull/713)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.11.0 to 2.11.1 (https://github.com/sigstore/fulcio/pull/714)
* Bump google.golang.org/protobuf from 1.28.0 to 1.28.1 (https://github.com/sigstore/fulcio/pull/710)
* Bump github/codeql-action from 2.1.16 to 2.1.17 (https://github.com/sigstore/fulcio/pull/709)
* Bump google.golang.org/api from 0.89.0 to 0.90.0 (https://github.com/sigstore/fulcio/pull/711)
* Bump golang from `f3d3d69` to `6e10f44` (https://github.com/sigstore/fulcio/pull/708)
* Bump google.golang.org/protobuf from 1.28.0 to 1.28.1 in /hack/tools (https://github.com/sigstore/fulcio/pull/712)
* Enable Scorecard badge (https://github.com/sigstore/fulcio/pull/706)
* Bump golang from `9349ed8` to `f3d3d69` (https://github.com/sigstore/fulcio/pull/707)
* Bump imjasonh/setup-ko from 0.4 to 0.5 (https://github.com/sigstore/fulcio/pull/704)
* Bump google.golang.org/api from 0.88.0 to 0.89.0 (https://github.com/sigstore/fulcio/pull/705)

## Contributors

* Azeem Shaikh (@azeemshaikh38)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Paul Thomson (@pauldthomson)

# v0.5.2

## Bug Fixes

* Ensure GetTrustBundle returns array of strings instead of a single string with newlines (https://github.com/sigstore/fulcio/pull/690)

## Miscellaneous

* Bump github.com/grpc-ecosystem/grpc-gateway/v2 in /hack/tools (https://github.com/sigstore/fulcio/pull/696)
* Bump google.golang.org/api from 0.87.0 to 0.88.0 (https://github.com/sigstore/fulcio/pull/694)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.10.3 to 2.11.0 (https://github.com/sigstore/fulcio/pull/https://github.com/sigstore/fulcio/pull/695)
* bump cosign to v1.9.0 (https://github.com/sigstore/fulcio/pull/692)
* Bump go.step.sm/crypto from 0.16.2 to 0.17.0 (https://github.com/sigstore/fulcio/pull/688)
* Bump actions/dependency-review-action from 2.0.2 to 2.0.4 (https://github.com/sigstore/fulcio/pull/686)
* Bump github.com/prometheus/common from 0.36.0 to 0.37.0 (https://github.com/sigstore/fulcio/pull/687)
* Bump golang from 1.18.3 to 1.18.4 (https://github.com/sigstore/fulcio/pull/683)
* Bump github/codeql-action from 2.1.15 to 2.1.16 (https://github.com/sigstore/fulcio/pull/684)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/https://github.com/sigstore/fulcio/pull/85)
* Bump google.golang.org/grpc from 1.47.0 to 1.48.0 (https://github.com/sigstore/fulcio/pull/682)
* Bump google.golang.org/api from 0.86.0 to 0.87.0 (https://github.com/sigstore/fulcio/pull/680)
* Bump cloud.google.com/go/security from 1.4.0 to 1.4.1 (https://github.com/sigstore/fulcio/pull/681)
* Bump github.com/prometheus/common from 0.35.0 to 0.36.0 (https://github.com/sigstore/fulcio/pull/678)
* Bump actions/setup-go from 3.2.0 to 3.2.1 (https://github.com/sigstore/fulcio/pull/677)

## Contributors

* Bob Callaway (@bobcallaway)

# v0.5.1

## Enhancements

* pipe all log messages to stdout for dev logger (https://github.com/sigstore/fulcio/pull/673)
* Add CORS support to HTTP endpoint (https://github.com/sigstore/fulcio/pull/670)
* generate OpenAPI documents from protobuf (https://github.com/sigstore/fulcio/pull/666)
* Add Tink signing backend (https://github.com/sigstore/fulcio/pull/645)
* Refactor in-memory signing CAs to use a single implementation (https://github.com/sigstore/fulcio/pull/644)
* change grpc response logger to debug level instead of error (https://github.com/sigstore/fulcio/pull/648)
* Add interface for certs/signer fetching to remove mutex (https://github.com/sigstore/fulcio/pull/643)

## Miscellaneous

* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/674)
* Update sigstore to pull in fixes (https://github.com/sigstore/fulcio/pull/671)
* Bump github.com/spiffe/go-spiffe/v2 from 2.1.0 to 2.1.1 (https://github.com/sigstore/fulcio/pull/668)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/669)
* add dependabot hack to monitor for new protoc releases (https://github.com/sigstore/fulcio/pull/667)
* Bump github/codeql-action from 2.1.14 to 2.1.15 (https://github.com/sigstore/fulcio/pull/663)
* Bump google.golang.org/api from 0.85.0 to 0.86.0 (https://github.com/sigstore/fulcio/pull/664)
* Bump ossf/scorecard-action from 1.1.1 to 1.1.2 (https://github.com/sigstore/fulcio/pull/662)
* Bump golang from `957001e` to `a452d62` (https://github.com/sigstore/fulcio/pull/661)
* Bump golang from `1c3d22f` to `957001e` (https://github.com/sigstore/fulcio/pull/660)
* Bump github/codeql-action from 2.1.13 to 2.1.14 (https://github.com/sigstore/fulcio/pull/659)
* Bump github/codeql-action from 2.1.12 to 2.1.13 (https://github.com/sigstore/fulcio/pull/656)
* Bump google.golang.org/api from 0.84.0 to 0.85.0 (https://github.com/sigstore/fulcio/pull/657)
* Bump github.com/spf13/cobra from 1.4.0 to 1.5.0 (https://github.com/sigstore/fulcio/pull/658)
* Bump github.com/prometheus/common from 0.34.0 to 0.35.0 (https://github.com/sigstore/fulcio/pull/655)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/653)
* Bump actions/dependency-review-action from 2.0.1 to 2.0.2 (https://github.com/sigstore/fulcio/pull/652)
* Bump golang from `b203dc5` to `1c3d22f` (https://github.com/sigstore/fulcio/pull/649)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/651)
* Bump actions/dependency-review-action from 1.0.2 to 2.0.1 (https://github.com/sigstore/fulcio/pull/650)
* Bump google.golang.org/api from 0.83.0 to 0.84.0 (https://github.com/sigstore/fulcio/pull/647)
* Bump google.golang.org/api from 0.82.0 to 0.83.0 (https://github.com/sigstore/fulcio/pull/642)

## Contributors

* Bob Callaway (@bobcallaway)
* Hayden Blauzvern (@haydentherapper)

# v0.5.0

## Enhancements

* code refactor (https://github.com/sigstore/fulcio/pull/626 / https://github.com/sigstore/fulcio/pull/620 /
https://github.com/sigstore/fulcio/pull/625 / https://github.com/sigstore/fulcio/pull/619 /
https://github.com/sigstore/fulcio/pull/604 / https://github.com/sigstore/fulcio/pull/599 /
https://github.com/sigstore/fulcio/pull/590 / https://github.com/sigstore/fulcio/pull/580 /
https://github.com/sigstore/fulcio/pull/561 / https://github.com/sigstore/fulcio/pull/558)
* Add API for fetching Fulcio configuration (https://github.com/sigstore/fulcio/pull/608)
* Split pkg/server from pkg/api (https://github.com/sigstore/fulcio/pull/616)
* Restict issuer claim mapping to email issuers (https://github.com/sigstore/fulcio/pull/606)
* Validate SPIFFE IDs and trust domains via library (https://github.com/sigstore/fulcio/pull/592)
* Use principal in CA abstraction (https://github.com/sigstore/fulcio/pull/570)
* googleca: Don't log all identities (https://github.com/sigstore/fulcio/pull/577)
* Small `ca` refactor (https://github.com/sigstore/fulcio/pull/569)
* Remove unused Subject field from code signing certificate (https://github.com/sigstore/fulcio/pull/568)
* Add client options testing (https://github.com/sigstore/fulcio/pull/562)
* Add timeout to OIDC discovery (https://github.com/sigstore/fulcio/pull/560)

## Bug Fixes

* spiffe: correct trust domain checking (https://github.com/sigstore/fulcio/pull/588)
* fix the digest image (https://github.com/sigstore/fulcio/pull/555)

## Documentation

* identity: improve the documentation for Principal.Name() (https://github.com/sigstore/fulcio/pull/579)

## Miscellaneous

* Use GenerateSerialNumber from cryptoutils (https://github.com/sigstore/fulcio/pull/571)
* challenges: remove ParseCSR (https://github.com/sigstore/fulcio/pull/578)
* Bump github/codeql-action from 2.1.11 to 2.1.12 (https://github.com/sigstore/fulcio/pull/629)
* Bump ossf/scorecard-action from 1.1.0 to 1.1.1 (https://github.com/sigstore/fulcio/pull/630)
* update cross-builder image to use go1.18.3 (https://github.com/sigstore/fulcio/pull/635)
* typo: Github -> GitHub (https://github.com/sigstore/fulcio/pull/636)
* Bump google.golang.org/api from 0.81.0 to 0.82.0 (https://github.com/sigstore/fulcio/pull/631)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.10.2 to 2.10.3 (https://github.com/sigstore/fulcio/pull/632)
* Bump golang from 1.18.2 to 1.18.3 (https://github.com/sigstore/fulcio/pull/628)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 in /hack/tools (https://github.com/sigstore/fulcio/pull/633)
* Bump google.golang.org/grpc from 1.46.2 to 1.47.0 (https://github.com/sigstore/fulcio/pull/627)
* Bump gopkg.in/yaml.v3 from 3.0.0 to 3.0.1 (https://github.com/sigstore/fulcio/pull/623)
* Bump actions/setup-go from 3.1.0 to 3.2.0 (https://github.com/sigstore/fulcio/pull/621)
* Bump github.com/spf13/viper from 1.11.0 to 1.12.0 (https://github.com/sigstore/fulcio/pull/622)
* Update sigstore to pull in go-tuf security fixes (https://github.com/sigstore/fulcio/pull/617)
* Bump ossf/scorecard-action from 1.0.4 to 1.1.0 (https://github.com/sigstore/fulcio/pull/618)
* Bump cloud.google.com/go/security from 1.3.0 to 1.4.0 (https://github.com/sigstore/fulcio/pull/613)
* Bump google.golang.org/api from 0.80.0 to 0.81.0 (https://github.com/sigstore/fulcio/pull/614)
* Bump actions/dependency-review-action from 1.0.1 to 1.0.2 (https://github.com/sigstore/fulcio/pull/609)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.10.1 to 2.10.2 (https://github.com/sigstore/fulcio/pull/610)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 in /hack/tools (https://github.com/sigstore/fulcio/pull/611)
* Add e2e test that tests IssuerClaim (https://github.com/sigstore/fulcio/pull/605)
* Bump actions/upload-artifact from 3.0.0 to 3.1.0 (https://github.com/sigstore/fulcio/pull/603)
* Added additional tests for CA implementations and OIDC (https://github.com/sigstore/fulcio/pull/602)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 in /hack/tools (https://github.com/sigstore/fulcio/pull/601)
* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.10.0 to 2.10.1 (https://github.com/sigstore/fulcio/pull/600)
* cmd/app: remove dependency on deprecated github.com/pkg/errors (https://github.com/sigstore/fulcio/pull/598)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/597)
* Bump github/codeql-action from 2.1.10 to 2.1.11 (https://github.com/sigstore/fulcio/pull/593)
* Bump go.step.sm/crypto from 0.16.1 to 0.16.2 (https://github.com/sigstore/fulcio/pull/594)
* Bump google.golang.org/api from 0.79.0 to 0.80.0 (https://github.com/sigstore/fulcio/pull/595)
* Skip tests that require network access with HERMETIC=true (https://github.com/sigstore/fulcio/pull/587)
* Bump github.com/google/certificate-transparency-go from 1.1.2 to 1.1.3 (https://github.com/sigstore/fulcio/pull/586)
* Bump google.golang.org/grpc from 1.46.0 to 1.46.2 (https://github.com/sigstore/fulcio/pull/585)
* Bump github.com/prometheus/client_golang from 1.12.1 to 1.12.2 (https://github.com/sigstore/fulcio/pull/584)
* Bump actions/setup-go from 3.0.0 to 3.1.0 (https://github.com/sigstore/fulcio/pull/582)
* Add some tests for challenges (https://github.com/sigstore/fulcio/pull/583)
* Bump actions/dependency-review-action (https://github.com/sigstore/fulcio/pull/581)
* Bump github/codeql-action (https://github.com/sigstore/fulcio/pull/572)
* Bump golangci/golangci-lint-action from 3.1.0 to 3.2.0 (https://github.com/sigstore/fulcio/pull/573)
* Update to use go1.18 (https://github.com/sigstore/fulcio/pull/576)
* Bump github.com/coreos/go-oidc/v3 from 3.1.0 to 3.2.0 (https://github.com/sigstore/fulcio/pull/574)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/575)
* update go to 1.17.10 (https://github.com/sigstore/fulcio/pull/567)
* Bump github/codeql-action from 2.1.9 to 2.1.10 (https://github.com/sigstore/fulcio/pull/565)
* Bump google.golang.org/api from 0.78.0 to 0.79.0 (https://github.com/sigstore/fulcio/pull/566)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/557)
* Bump google.golang.org/api from 0.77.0 to 0.78.0 (https://github.com/sigstore/fulcio/pull/556)
* update go builder image and cosign image (https://github.com/sigstore/fulcio/pull/554)
* add changelog for 0.4.1 release (https://github.com/sigstore/fulcio/pull/553)


## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Jason Hall (@imjasonh)
* Koichi Shiraishi (@zchee)
* Miloslav Trmač (@mtrmac)
* Nathan Smith (@nsmith5)

# v0.4.1

## Bug Fixes

* Fix key usage for issued certificates (https://github.com/sigstore/fulcio/pull/549)

## Documentation

* Add note about the status of the legacy HTTP API. (https://github.com/sigstore/fulcio/pull/531)

## Others

* Bump google.golang.org/api from 0.76.0 to 0.77.0 (https://github.com/sigstore/fulcio/pull/552)
* chore(deps): Included dependency review (https://github.com/sigstore/fulcio/pull/540)
* Add @haydentherapper to CODEOWNERS (https://github.com/sigstore/fulcio/pull/548)
* Bump github.com/google/go-cmp from 0.5.7 to 0.5.8 (https://github.com/sigstore/fulcio/pull/544)
* Bump github.com/fsnotify/fsnotify from 1.5.3 to 1.5.4 (https://github.com/sigstore/fulcio/pull/543)
* Bump google.golang.org/api from 0.75.0 to 0.76.0 (https://github.com/sigstore/fulcio/pull/542)
* Bump github/codeql-action from 2.1.8 to 2.1.9 (https://github.com/sigstore/fulcio/pull/545)
* Bump github.com/googleapis/api-linter in /hack/tools (https://github.com/sigstore/fulcio/pull/546)
* Bump google.golang.org/grpc from 1.45.0 to 1.46.0 (https://github.com/sigstore/fulcio/pull/541)

## Contributors

* Bob Callaway (@bobcallaway)
* Hayden Blauzvern (@haydentherapper)
* Naveen (@naveensrinivasan)
* Zack Newman (@znewman01)

# v0.4.0

## Enhancements

* Add CSR support for key delivery and proof of possession (https://github.com/sigstore/fulcio/pull/527)
* Remove checked in binary (https://github.com/sigstore/fulcio/pull/524)
* add GRPC interface (https://github.com/sigstore/fulcio/pull/472)
* Embed SCTs in issued certificates (https://github.com/sigstore/fulcio/pull/507)
* Add intermediate CA implementation with KMS-backed signer (https://github.com/sigstore/fulcio/pull/496)

## Bug Fixes

* Fix null pointer crash and incorrect error statuses (https://github.com/sigstore/fulcio/pull/526)

## Documentation

* Add documentation for setting up Fulcio instance (https://github.com/sigstore/fulcio/pull/521)
* Add documentation for CT log (https://github.com/sigstore/fulcio/pull/514)
* examples: This adds example code on how to fetch a fulcio certificate (https://github.com/sigstore/fulcio/pull/324)

## Others

* Bump github.com/grpc-ecosystem/grpc-gateway/v2 from 2.8.0 to 2.10.0 (https://github.com/sigstore/fulcio/pull/523)
* Bump actions/checkout from 3.0.0 to 3.0.1 (https://github.com/sigstore/fulcio/pull/522)
* Bump google.golang.org/protobuf from 1.27.1 to 1.28.0 in /hack/tools (https://github.com/sigstore/fulcio/pull/520)
* Update release images (https://github.com/sigstore/fulcio/pull/517)
* Bump github.com/spf13/viper from 1.10.1 to 1.11.0 (https://github.com/sigstore/fulcio/pull/516)
* Bump github/codeql-action from 2.1.7 to 2.1.8 (https://github.com/sigstore/fulcio/pull/513)
* add changelog for v0.3.0 release (https://github.com/sigstore/fulcio/pull/508)

## Contributors

* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Morten Linderud (@Foxboron)

# v0.3.0

## Enhancements

* Generate larger, compliant serial numbers (https://github.com/sigstore/fulcio/pull/500)
* Use provided HTTP client instead when fetching root cert (https://github.com/sigstore/fulcio/pull/502)
* Add missing reader lock to File CA when reading certificate chain (https://github.com/sigstore/fulcio/pull/493)
* Add validation of public keys to prevent certifying weak keys (https://github.com/sigstore/fulcio/pull/490)
* Refactor API tests (https://github.com/sigstore/fulcio/pull/483)
* Update Username OIDC flow based on comments  (https://github.com/sigstore/fulcio/pull/463)

## Bug Fixes

* fix_certificate_readme_typos (https://github.com/sigstore/fulcio/pull/487)
* Fix minor typs in security model README (https://github.com/sigstore/fulcio/pull/488)
* Fix minor typos in README (https://github.com/sigstore/fulcio/pull/486)
* fix build date format for version command (https://github.com/sigstore/fulcio/pull/484)

## Others

* update cosign and golang-cross images (https://github.com/sigstore/fulcio/pull/506)
* Bump codecov/codecov-action from 2.1.0 to 3 (https://github.com/sigstore/fulcio/pull/505)
* Bump github/codeql-action from 2.1.6 to 2.1.7 (https://github.com/sigstore/fulcio/pull/504)
* Bump go.step.sm/crypto from 0.16.0 to 0.16.1 (https://github.com/sigstore/fulcio/pull/498)
* Bump github/codeql-action from 1.1.5 to 2.1.6 (https://github.com/sigstore/fulcio/pull/497)
* Bump google.golang.org/api from 0.73.0 to 0.74.0 (https://github.com/sigstore/fulcio/pull/499)
* Bump github.com/prometheus/common from 0.32.1 to 0.33.0 (https://github.com/sigstore/fulcio/pull/491)
* Bump google.golang.org/protobuf from 1.27.1 to 1.28.0 (https://github.com/sigstore/fulcio/pull/485)
* Fix concurrency properly in File CA implementation (https://github.com/sigstore/fulcio/pull/495)
* Bump go.step.sm/crypto from 0.15.3 to 0.16.0 (https://github.com/sigstore/fulcio/pull/482)
* Bump google.golang.org/api from 0.72.0 to 0.73.0 (https://github.com/sigstore/fulcio/pull/479)
* Bump github.com/stretchr/testify from 1.7.0 to 1.7.1 (https://github.com/sigstore/fulcio/pull/478)
* Bump github/codeql-action from 1.1.4 to 1.1.5 (https://github.com/sigstore/fulcio/pull/477)
* Bump google.golang.org/api from 0.71.0 to 0.72.0 (https://github.com/sigstore/fulcio/pull/476)
* Bump go.step.sm/crypto from 0.15.2 to 0.15.3 (https://github.com/sigstore/fulcio/pull/473)

## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Jason Hall (@imjasonh)
* John Speed Meyers (@jspeed-meyers)

# v0.2.0

## Enhancements

* Use fulcio-system ns and drop -dev suffix for sa (https://github.com/sigstore/fulcio/pull/418)
* Return an error if we fail get get the Root cert. (https://github.com/sigstore/fulcio/pull/416)
* Add unit tests for oidc-EmailFromIDToken method (https://github.com/sigstore/fulcio/pull/413)
* extract CA/KMS support info to separate file (https://github.com/sigstore/fulcio/pull/409)
* add securityContext to deployment (https://github.com/sigstore/fulcio/pull/420)
* Count HTTP request error codes with prometheus (https://github.com/sigstore/fulcio/pull/396)
* Remove organization from subject for GCP CAS issuer (https://github.com/sigstore/fulcio/pull/391)
* Update warning text. (https://github.com/sigstore/fulcio/pull/389)
* Improve error messages returned by SigningCert (https://github.com/sigstore/fulcio/pull/388)
* Allow parameterized application/json content types (https://github.com/sigstore/fulcio/pull/386)
* Add AKS MetaIssuer (https://github.com/sigstore/fulcio/pull/384)
* Move CTL logging logic over to CTL package (https://github.com/sigstore/fulcio/pull/353)
* Move OID information to docs directory and reformat (https://github.com/sigstore/fulcio/pull/378)
* Upgrade miekg/pkcs11 using 'go get github.com/miekg/pkcs11@v1.1.1' (https://github.com/sigstore/fulcio/pull/376)
* Address signingCert panic with the last-byte calculation of finalChainPEM (https://github.com/sigstore/fulcio/pull/370)
* Include instructions to download verify the fulcio root certificate with TUF (https://github.com/sigstore/fulcio/pull/361)
* Make CA explicit dependency of API handler (https://github.com/sigstore/fulcio/pull/354)
* Improve error message when an invalid OIDC issuer is provided (https://github.com/sigstore/fulcio/pull/357)
* Make the the invalid CA error message actionable (https://github.com/sigstore/fulcio/pull/356)
* Initialize CT log client once (https://github.com/sigstore/fulcio/pull/350)
* Generate subject key ID correctly for non-GCP certs (https://github.com/sigstore/fulcio/pull/345)
* Add chain in response for all CAs, fix newlines in response (https://github.com/sigstore/fulcio/pull/341)
* Add some reasonable timeouts to API server (https://github.com/sigstore/fulcio/pull/337)
* fileca: add support for intermediate certificates (https://github.com/sigstore/fulcio/pull/320)
* Set max request size to 4MiB (https://github.com/sigstore/fulcio/pull/338)
* Extract additional claims  from github-workflow token (https://github.com/sigstore/fulcio/pull/306)
* Enable server settings via config file and env vars (https://github.com/sigstore/fulcio/pull/315)
* Add file backed certificate authority (https://github.com/sigstore/fulcio/pull/280)
* Handle error when there are no roots returned by CA Service (https://github.com/sigstore/fulcio/pull/298)
* Add RootCert method to client + tests (https://github.com/sigstore/fulcio/pull/290)
* Add back support for building with CGO_ENABLED=0 (https://github.com/sigstore/fulcio/pull/293)
* add usersnames list to the codeonwers to make it easier to check (https://github.com/sigstore/fulcio/pull/295)
* Add a Root Cert method to the CA interface, and implement it. (https://github.com/sigstore/fulcio/pull/287)
* Update readme for V1 CA Service (https://github.com/sigstore/fulcio/pull/286)
* Fail fast if private key is not found when using PKCS11 CA (https://github.com/sigstore/fulcio/pull/285)
* Do not close the PKCS11 context on startup (https://github.com/sigstore/fulcio/pull/282)
* Localize flags to each subcommand (https://github.com/sigstore/fulcio/pull/274)
* Make client request timeout configurable with `WithTimeout` client option (https://github.com/sigstore/fulcio/pull/272)
* add the ability to set the user-agent string on requests from the `Client` (https://github.com/sigstore/fulcio/pull/264)
* Consolidate the source-of-truth. (https://github.com/sigstore/fulcio/pull/263)
* Move the deployment to the new v1 cert. (https://github.com/sigstore/fulcio/pull/261)
* The v1 GCP CA requires this field to be set. (https://github.com/sigstore/fulcio/pull/260)
* Experiment with FulcioConfig pulling from context.Context (https://github.com/sigstore/fulcio/pull/249)
* Upgrade fulcios to use of the google privateca api at v1 (https://github.com/sigstore/fulcio/pull/218)
* plumb through !cgo golang tags that removes pkcs11 support (https://github.com/sigstore/fulcio/pull/244)
* break out CA-specific implementation from common API class (https://github.com/sigstore/fulcio/pull/220)
* Add support for recoginizing allow.pub as an spiffe issuer (https://github.com/sigstore/fulcio/pull/228)
* Various nits trying SoftHSM (https://github.com/sigstore/fulcio/pull/217)
* Use MetaIssuers to simular EKS / GKE in e2e test. (https://github.com/sigstore/fulcio/pull/225)
* Add support for "meta issuers". (https://github.com/sigstore/fulcio/pull/223)
* Remove the cluster-local block by default. (https://github.com/sigstore/fulcio/pull/224)
* Refactor the way we access `Config` (https://github.com/sigstore/fulcio/pull/222)
* Enable Fulcio e2e testing. (https://github.com/sigstore/fulcio/pull/219)
* use sigstore/sigstore instead of directly calling RSA/ECDSA verify calls (https://github.com/sigstore/fulcio/pull/221)
* Refactor the kind e2e test. (https://github.com/sigstore/fulcio/pull/215)
* Add issuer information to code signing certificates (https://github.com/sigstore/fulcio/pull/204)
* Extract the OIDC issuer URL. (https://github.com/sigstore/fulcio/pull/211)
* use request ID logger where possible (https://github.com/sigstore/fulcio/pull/209)
* Rewrite "FulcioCA" to "PKCS11CA" and add AWS support (https://github.com/sigstore/fulcio/pull/187)
* add pkcs11-config-path command line parameter (https://github.com/sigstore/fulcio/pull/192)
* Add GitHub OIDC to Fulcio (https://github.com/sigstore/fulcio/pull/181)
* Changes fulcio-server to fulcio (https://github.com/sigstore/fulcio/pull/186)
* Add Github to `fulcioca` path. (https://github.com/sigstore/fulcio/pull/184)
* Add support for Github OIDC (https://github.com/sigstore/fulcio/pull/180)
* Generate client code with swagger in Makefile (https://github.com/sigstore/fulcio/pull/176)
* Switch to the JSON logger in prod (https://github.com/sigstore/fulcio/pull/175)
* add SCT as HTTP response header (https://github.com/sigstore/fulcio/pull/163)
* fulcio: add version command (https://github.com/sigstore/fulcio/pull/155)
* Script and process to generate OIDC config from federation directory. (https://github.com/sigstore/fulcio/pull/139)


## Bug Fixes

* Fix the SCT header return value from the API to base64 encode it. (https://github.com/sigstore/fulcio/pull/288)
* Fix the k8s subject parsing. (https://github.com/sigstore/fulcio/pull/254)
* [Correction] Upgrade fulcios to use of the google privateca api at v1 (https://github.com/sigstore/fulcio/pull/252)
* fix: go get complain missing version when dir not in module (https://github.com/sigstore/fulcio/pull/248)
* Fix street-address and postal-code descriptions to be more descriptive. (https://github.com/sigstore/fulcio/pull/245)
* fix cutpaste error, sets cpu correctly (https://github.com/sigstore/fulcio/pull/237)
* Fix nil pointer, update dev docs (https://github.com/sigstore/fulcio/pull/236)
* Fix the Github OIDC challenge endpoint (https://github.com/sigstore/fulcio/pull/206)
* Fix misspellings. (https://github.com/sigstore/fulcio/pull/177)

## Documentation

* extract development documentation from README (https://github.com/sigstore/fulcio/pull/410)
* fixing link to external resources (https://github.com/sigstore/fulcio/pull/411)
* Add feature stability and deprecation docs (https://github.com/sigstore/fulcio/pull/400)
* docs: overview of certificate issuing (https://github.com/sigstore/fulcio/pull/383)
* Add Logo to README (https://github.com/sigstore/fulcio/pull/381)
* Move sec model out of readme (https://github.com/sigstore/fulcio/pull/382)
* Update README for V1 Fulcio cert (https://github.com/sigstore/fulcio/pull/355)
* fix link for SECURITY.md (https://github.com/sigstore/fulcio/pull/340)
* Remove root CA whitespaces on README.md (https://github.com/sigstore/fulcio/pull/325)
* Add Locust load test and README (https://github.com/sigstore/fulcio/pull/311)
* add oid documentation (https://github.com/sigstore/fulcio/pull/307)
* Add documentation for testing with `ephemeralca` as well as document (https://github.com/sigstore/fulcio/pull/296)

## Others

* Bump actions/upload-artifact from 2.3.1 to 3 (https://github.com/sigstore/fulcio/pull/452)
* Go update to 1.17.8 and cosign to 1.6.0 (https://github.com/sigstore/fulcio/pull/453)
* add missing target name (https://github.com/sigstore/fulcio/pull/450)
* Bump cloud.google.com/go/security from 1.2.1 to 1.3.0 (https://github.com/sigstore/fulcio/pull/448)
* Bump golang from `c2ca472` to `b983574` (https://github.com/sigstore/fulcio/pull/447)
* Move CI private-ca YAML to subdir (https://github.com/sigstore/fulcio/pull/446)
* Add step in release to mirror signed image to ghcr (https://github.com/sigstore/fulcio/pull/441)
* Bump actions/checkout from 2 to 3 (https://github.com/sigstore/fulcio/pull/443)
* Bump golang from `e06c834` to `c2ca472` (https://github.com/sigstore/fulcio/pull/442)
* Bump actions/setup-go from 2.2.0 to 3.0.0 (https://github.com/sigstore/fulcio/pull/440)
* Bump golangci/golangci-lint-action from 3.0.0 to 3.1.0 (https://github.com/sigstore/fulcio/pull/439)
* Bump golangci/golangci-lint-action from 2.5.2 to 3 (https://github.com/sigstore/fulcio/pull/438)
* Bump github/codeql-action from 1.1.2 to 1.1.3 (https://github.com/sigstore/fulcio/pull/435)
* Bump github.com/magiconair/properties from 1.8.5 to 1.8.6 (https://github.com/sigstore/fulcio/pull/436)
* add indent to fix yaml error (https://github.com/sigstore/fulcio/pull/434)
* Bump cloud.google.com/go/security from 1.2.0 to 1.2.1 (https://github.com/sigstore/fulcio/pull/431)
* explicitly set permissions for github workflows (https://github.com/sigstore/fulcio/pull/433)
* Bump google.golang.org/api from 0.69.0 to 0.70.0 (https://github.com/sigstore/fulcio/pull/432)
* Add missing testing dependency (https://github.com/sigstore/fulcio/pull/429)
* Workflow to kick off release. (https://github.com/sigstore/fulcio/pull/407)
* Take advantage of Chainguard maintained versions of various actions. (https://github.com/sigstore/fulcio/pull/427)
* Bump golang from `2c92978` to `e06c834` (https://github.com/sigstore/fulcio/pull/426)
* create namespace as part of config yaml (https://github.com/sigstore/fulcio/pull/422)
* Bump golang from `1a35cc2` to `2c92978` (https://github.com/sigstore/fulcio/pull/423)
* Bump ossf/scorecard-action from 1.0.3 to 1.0.4 (https://github.com/sigstore/fulcio/pull/425)
* Bump github/codeql-action from 1.1.0 to 1.1.2 (https://github.com/sigstore/fulcio/pull/424)
* Bump google.golang.org/api from 0.68.0 to 0.69.0 (https://github.com/sigstore/fulcio/pull/412)
* Bump cloud.google.com/go/security from 1.1.1 to 1.2.0 (https://github.com/sigstore/fulcio/pull/408)
* Bump github/codeql-action from 1.0.32 to 1.1.0 (https://github.com/sigstore/fulcio/pull/406)
* update cross-build to use go 1.17.7 (https://github.com/sigstore/fulcio/pull/404)
* Bump golang from 1.17.6 to 1.17.7 (https://github.com/sigstore/fulcio/pull/403)
* Bump golang from `301609e` to `fff998d` (https://github.com/sigstore/fulcio/pull/401)
* Bump actions/setup-go from 2.1.5 to 2.2.0 (https://github.com/sigstore/fulcio/pull/402)
* Bump google.golang.org/api from 0.67.0 to 0.68.0 (https://github.com/sigstore/fulcio/pull/399)
* Bump go.uber.org/zap from 1.20.0 to 1.21.0 (https://github.com/sigstore/fulcio/pull/393)
* Bump github/codeql-action from 1.0.31 to 1.0.32 (https://github.com/sigstore/fulcio/pull/392)
* Bump google.golang.org/api from 0.66.0 to 0.67.0 (https://github.com/sigstore/fulcio/pull/385)
* Bump github/codeql-action from 1.0.30 to 1.0.31 (https://github.com/sigstore/fulcio/pull/366)
* Bump ossf/scorecard-action from 1.0.2 to 1.0.3 (https://github.com/sigstore/fulcio/pull/367)
* Bump go.step.sm/crypto from 0.15.0 to 0.15.1 (https://github.com/sigstore/fulcio/pull/377)
* Bump google.golang.org/api from 0.65.0 to 0.66.0 (https://github.com/sigstore/fulcio/pull/363)
* Bump github.com/prometheus/client_golang from 1.12.0 to 1.12.1 (https://github.com/sigstore/fulcio/pull/362)
* Bump golang from `d7f2f6f` to `301609e` (https://github.com/sigstore/fulcio/pull/358)
* Bump go.step.sm/crypto from 0.14.0 to 0.15.0 (https://github.com/sigstore/fulcio/pull/359)
* Bump golang from `0fa6504` to `d7f2f6f` (https://github.com/sigstore/fulcio/pull/352)
* createca: Address panic when no private key pair matches (https://github.com/sigstore/fulcio/pull/351)
* update version marker (https://github.com/sigstore/fulcio/pull/346)
* Remove Google CA v1beta1 API and associated config (https://github.com/sigstore/fulcio/pull/349)
* Bump ossf/scorecard-action from 1.0.1 to 1.0.2 (https://github.com/sigstore/fulcio/pull/347)
* update to v1.0.29 of codeql-action (https://github.com/sigstore/fulcio/pull/344)
* Bump github.com/prometheus/client_golang from 1.11.0 to 1.12.0 (https://github.com/sigstore/fulcio/pull/333)
* Bump github.com/google/go-cmp from 0.5.6 to 0.5.7 (https://github.com/sigstore/fulcio/pull/334)
* Update github/codeql-action requirement to 8a4b243fbf9a03a93e93a71c1ec257347041f9c4 (https://github.com/sigstore/fulcio/pull/332)
* Bump ossf/scorecard-action from 0fe1afdc40f536c78e3dc69147b91b3ecec2cc8a to 1.0.1 (https://github.com/sigstore/fulcio/pull/331)
* pin one additional set of actions (https://github.com/sigstore/fulcio/pull/329)
* Bump google.golang.org/api from 0.64.0 to 0.65.0 (https://github.com/sigstore/fulcio/pull/321)
* add OSSF scorecard action (https://github.com/sigstore/fulcio/pull/328)
* Bump golang from `8c0269d` to `0fa6504` (https://github.com/sigstore/fulcio/pull/326)
* pin github actions by digest instead of tag (https://github.com/sigstore/fulcio/pull/323)
* release: add cloudbuild to run the release for fulcio (https://github.com/sigstore/fulcio/pull/322)
* Fix docker-compose dexidp startup (https://github.com/sigstore/fulcio/pull/316)
* Bump go.step.sm/crypto from 0.13.0 to 0.14.0 (https://github.com/sigstore/fulcio/pull/319)
* Bump golang from 1.17.5 to 1.17.6 (https://github.com/sigstore/fulcio/pull/317)
* Switch to use fileca in e2e tests (https://github.com/sigstore/fulcio/pull/309)
* Bump google.golang.org/api from 0.63.0 to 0.64.0 (https://github.com/sigstore/fulcio/pull/318)
* Remove hack/tools (https://github.com/sigstore/fulcio/pull/308)
* Bump cloud.google.com/go/security from 1.1.0 to 1.1.1 (https://github.com/sigstore/fulcio/pull/312)
* Bump go.uber.org/zap from 1.19.1 to 1.20.0 (https://github.com/sigstore/fulcio/pull/313)
* Bump github.com/sigstore/sigstore from 1.0.1 to 1.1.0 (https://github.com/sigstore/fulcio/pull/299)
* Change ports for docker compose to avoid conflict with Rekor (https://github.com/sigstore/fulcio/pull/297)
* Bump github.com/spf13/viper from 1.10.0 to 1.10.1 (https://github.com/sigstore/fulcio/pull/283)
* Bump github.com/spf13/cobra from 1.2.1 to 1.3.0 (https://github.com/sigstore/fulcio/pull/278)
* Bump golang from 1.17.4 to 1.17.5 (https://github.com/sigstore/fulcio/pull/269)
* Bump github.com/prometheus/common from 0.29.0 to 0.32.1 (https://github.com/sigstore/fulcio/pull/270)
* Bump golang from 1.17.3 to 1.17.4 (https://github.com/sigstore/fulcio/pull/265)
* Wrap the server with the Prometheus so we get metrics + add an e2e te… (https://github.com/sigstore/fulcio/pull/267)
* While working on #267 noticed this, but didn't want to bake into it. (https://github.com/sigstore/fulcio/pull/268)
* Drop OpenAPI from Fulcio (https://github.com/sigstore/fulcio/pull/262)
* Drop useless package. (https://github.com/sigstore/fulcio/pull/259)
* Drop gratuitous `sync.Once` in google CAs. (https://github.com/sigstore/fulcio/pull/258)
* Remove `viper` from `pkg/`. (https://github.com/sigstore/fulcio/pull/257)
* Bump github.com/mitchellh/mapstructure from 1.4.2 to 1.4.3 (https://github.com/sigstore/fulcio/pull/256)
* Consolidate `viper` usage in `pkg/ca/ca.go` (https://github.com/sigstore/fulcio/pull/255)
* Bump cloud.google.com/go/security from 0.1.0 to 1.1.0 (https://github.com/sigstore/fulcio/pull/246)
* Bump github.com/go-openapi/strfmt from 0.21.0 to 0.21.1 (https://github.com/sigstore/fulcio/pull/247)
* Use `CGO_ENABLED=1` via `.ko.yaml`. (https://github.com/sigstore/fulcio/pull/242)
* Bump github.com/sigstore/sigstore from 1.0.0 to 1.0.1 (https://github.com/sigstore/fulcio/pull/239)
* Add commit sha and trigger to github workflow (https://github.com/sigstore/fulcio/pull/232)
* Bump golang from 1.17.2 to 1.17.3 (https://github.com/sigstore/fulcio/pull/234)
* Bump actions/checkout from 2.3.5 to 2.4.0 (https://github.com/sigstore/fulcio/pull/233)
* Bump github.com/go-openapi/runtime from 0.20.0 to 0.21.0 (https://github.com/sigstore/fulcio/pull/229)
* Bump github.com/go-openapi/strfmt from 0.20.3 to 0.21.0 (https://github.com/sigstore/fulcio/pull/226)
* Bump github.com/hashicorp/golang-lru from 0.5.3 to 0.5.4 (https://github.com/sigstore/fulcio/pull/227)
* bump go-swagger to v0.28.0 (https://github.com/sigstore/fulcio/pull/213)
* Reproducible builds with trimpath (https://github.com/sigstore/fulcio/pull/210)
* Bump actions/checkout from 2.3.4 to 2.3.5 (https://github.com/sigstore/fulcio/pull/207)
* Bump github.com/go-openapi/runtime from 0.19.31 to 0.20.0 (https://github.com/sigstore/fulcio/pull/202)
* Bump github.com/go-openapi/spec from 0.20.3 to 0.20.4 (https://github.com/sigstore/fulcio/pull/201)
* Bump github.com/go-openapi/validate from 0.20.2 to 0.20.3 (https://github.com/sigstore/fulcio/pull/198)
* update go.sum (https://github.com/sigstore/fulcio/pull/205)
* Bump github.com/go-openapi/loads from 0.20.2 to 0.20.3 (https://github.com/sigstore/fulcio/pull/200)
* Bump github.com/go-openapi/strfmt from 0.20.2 to 0.20.3 (https://github.com/sigstore/fulcio/pull/199)
* Bump golang from 1.17.1 to 1.17.2 (https://github.com/sigstore/fulcio/pull/197)
* Bump github.com/spf13/viper from 1.8.1 to 1.9.0 (https://github.com/sigstore/fulcio/pull/189)
* Bump github.com/coreos/go-oidc/v3 from 3.0.0 to 3.1.0 (https://github.com/sigstore/fulcio/pull/188)
* Bump github.com/mitchellh/mapstructure from 1.4.1 to 1.4.2 (https://github.com/sigstore/fulcio/pull/185)
* Bump github.com/ThalesIgnite/crypto11 from 1.2.4 to 1.2.5 (https://github.com/sigstore/fulcio/pull/182)
* Bump golang from 1.17.0 to 1.17.1 (https://github.com/sigstore/fulcio/pull/179)
* Bump go.uber.org/zap from 1.19.0 to 1.19.1 (https://github.com/sigstore/fulcio/pull/178)
* Bump github.com/go-openapi/runtime from 0.19.30 to 0.19.31 (https://github.com/sigstore/fulcio/pull/171)
* Bump github.com/go-openapi/errors from 0.20.0 to 0.20.1 (https://github.com/sigstore/fulcio/pull/169)
* Bump github.com/go-openapi/strfmt from 0.20.1 to 0.20.2 (https://github.com/sigstore/fulcio/pull/168)
* Bump golang from 1.16.7 to 1.17.0 (https://github.com/sigstore/fulcio/pull/166)
* Bump cloud.google.com/go from 0.91.1 to 0.92.3 (https://github.com/sigstore/fulcio/pull/167)
* Bump cloud.google.com/go from 0.90.0 to 0.91.1 (https://github.com/sigstore/fulcio/pull/162)
* Bump github.com/go-openapi/runtime from 0.19.29 to 0.19.30 (https://github.com/sigstore/fulcio/pull/161)
* Bump go.uber.org/zap from 1.18.1 to 1.19.0 (https://github.com/sigstore/fulcio/pull/160)
* Bump golang from 1.16.6 to 1.16.7 (https://github.com/sigstore/fulcio/pull/159)
* Bump cloud.google.com/go from 0.89.0 to 0.90.0 (https://github.com/sigstore/fulcio/pull/158)
* Bump cloud.google.com/go from 0.88.0 to 0.89.0 (https://github.com/sigstore/fulcio/pull/156)
* makefile: add rule to download and set swagger and make rule to build the dist (https://github.com/sigstore/fulcio/pull/154)
* Add missing code of conduct (stock sigstore one) (https://github.com/sigstore/fulcio/pull/153)

## Contributors

* Appu (@loosebazooka)
* Asra Ali (@asraa)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Christian Kotzbauer (@ckotzbauer)
* Dan Lorenc (@dlorenc)
* Elizabeth Thomas (@elizabetht)
* Evan Phoenix (@evanphx)
* Hayden Blauzvern (@haydentherapper)
* Jake Sanders (@dekkagaijin)
* Josh Dolitsky (@jdolitsky)
* Jyotsna (@jyotsna-penumaka)
* Kenny Leung (@k4leung4)
* Luke Hinds (@lukehinds)
* Mark Bestavros (@mbestavros)
* Matt Moore (@mattmoor)
* Matthew Suozzo (@msuozzo)
* Nathan Smith (@nsmith5)
* Naveen (@naveensrinivasan)
* Nghia Tran (@tcnghias)
* Priya Wadhwa (@priyawadhwa)
* Radoslav Gerganov (@rgerganov)
* Rafael Fernández López (@ereslibre)
* Scott Nichols (@n3wscott)
* Thomas Strömberg (@tstromberg)
* Tuan Anh Tran (@tuananh)
* Viacheslav Vasilyev (@avoidik)
* Ville Aikas (@vaikas)
* Zack Newman (@znewman01)
* endorama (@endorama)
