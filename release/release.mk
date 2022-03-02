##################
# release section
##################

# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	LDFLAGS="$(LDFLAGS)" goreleaser release

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	LDFLAGS="$(LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist


##################
# images section
##################

ALL_ARCH = amd64 arm arm64 ppc64le s390x

.PHONY: ko-release
ko-release:
# amd64
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko resolve --base-import-paths \
		--platform=linux/amd64 --tags $(GIT_VERSION)-amd64 --tags $(GIT_HASH)-amd64 \
		--filename config/ > $(FULCIO_YAML)

# arm64
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	CC=aarch64-linux-gnu-gcc \
	ko publish --base-import-paths \
		--platform=linux/arm64 --tags $(GIT_VERSION)-arm64 --tags $(GIT_HASH)-arm64 \
		github.com/sigstore/fulcio

# arm
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	CC=arm-linux-gnueabihf-gcc \
	ko publish --base-import-paths \
		--platform=linux/arm --tags $(GIT_VERSION)-arm --tags $(GIT_HASH)-arm \
		github.com/sigstore/fulcio

# ppc64le
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	CC=powerpc64le-linux-gnu-gcc \
	ko publish --base-import-paths \
		--platform=linux/ppc64le --tags $(GIT_VERSION)-ppc64le --tags $(GIT_HASH)-ppc64le \
		github.com/sigstore/fulcio

# s390x
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	CC=s390x-linux-gnu-gcc \
	ko publish --base-import-paths \
		--platform=linux/s390x --tags $(GIT_VERSION)-s390x --tags $(GIT_HASH)-s390x \
		github.com/sigstore/fulcio

.PHONY: push-manifest
push-manifest:
	docker manifest create --amend $(KO_PREFIX)/fulcio:$(GIT_VERSION) $(shell echo $(ALL_ARCH) | sed -e "s~[^ ]*~$(KO_PREFIX)/fulcio:$(GIT_VERSION)\-&~g")
	@for arch in $(ALL_ARCH); do docker manifest annotate --arch $${arch} ${KO_PREFIX}/fulcio:${GIT_VERSION} ${KO_PREFIX}/fulcio:${GIT_VERSION}-$${arch}; done
	docker manifest push --purge ${KO_PREFIX}/fulcio:${GIT_VERSION}

	docker manifest create --amend $(KO_PREFIX)/fulcio:$(GIT_HASH) $(shell echo $(ALL_ARCH) | sed -e "s~[^ ]*~$(KO_PREFIX)/fulcio:$(GIT_HASH)\-&~g")
	@for arch in $(ALL_ARCH); do docker manifest annotate --arch $${arch} ${KO_PREFIX}/fulcio:${GIT_HASH} ${KO_PREFIX}/fulcio:${GIT_HASH}-$${arch}; done
	docker manifest push --purge ${KO_PREFIX}/fulcio:${GIT_HASH}

.PHONY: update-yaml
update-yaml:
	sed -i -e 's;$(KO_PREFIX)/fulcio:.*;$(KO_PREFIX)/fulcio:$(GIT_HASH)/g' $(FULCIO_YAML)

.PHONY: release-images
release-images: ko-release push-manifest update-yaml

###########################
# sign with GCP KMS section
###########################

.PHONY: sign-container-release
sign-container-release: release-images
	cosign sign --force --key "gcpkms://projects/${PROJECT_ID}/locations/${KEY_LOCATION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}/versions/${KEY_VERSION}" -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/fulcio:$(GIT_VERSION)

######################
# sign keyless section
######################

.PHONY: sign-keyless-release
sign-keyless-release:
	cosign sign --force -a GIT_HASH=$(GIT_HASH) -a GIT_VERSION=$(GIT_VERSION) ${KO_PREFIX}/fulcio:$(GIT_VERSION)

####################
# copy image to GHCR
####################

.PHONY: copy-signed-release-to-ghcr
	cosign copy ${KO_PREFIX}/fulcio:$(GIT_VERSION) ${GHCR_PREFIX}/fulcio:$(GIT_VERSION)
