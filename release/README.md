# Releasing Fulcio

## Publishing updated binaries and container

This guide assumes that `upstream` references `github.com/sigstore/fulcio`.

1. Release notes: Create a PR to update and review release notes in `CHANGELOG.md`.

Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.

You can get a list of pull requests since the last release by substituting in the date of the last release and running:

```shell
git log --pretty="* %s" --after="YYYY-MM-DD"
```

and a list of authors by running:

```shell
git log --pretty="* %an" --after="YYYY-MM-DD" | sort -u
```

2. Create and push a new tag. Note that you can't create a tag without creating a release in the GitHub UI, so you'll need to do this locally.

**WARNING**: Tags should not be updated to a new ref or deleted/recreated after creation. Go provides a [checksum database](https://sum.golang.org/)
that persists an immutable mapping between version and ref, and updating the tag will break clients that have already downloaded the release.

```shell
git pull upstream main
export RELEASE_TAG=v1.2.3 # Specify version
git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
git push upstream ${RELEASE_TAG}
```

After the tag is pushed, the [Create release, push container image](https://github.com/sigstore/fulcio/actions/workflows/release.yml) workflow will kick off. It will:
* Build and attest the release binaries and create a draft GitHub release
* Build, push, and attest the multi-arch container image on `ghcr.io/sigstore/fulcio`
* Sign the release binaries and container image using the GCP KMS release key and upload the `.sigstore.json` bundles and `release-cosign.pub` to the draft release
* Copy the container image and its attestations/signatures to `gcr.io/projectsigstore/fulcio`

Once the workflow finishes, go to [Releases](https://github.com/sigstore/fulcio/releases), select
the latest draft release, add release notes, and publish it.

## Updating the infrastructure

Update the [Helm chart](https://github.com/sigstore/helm-charts/tree/main/charts/fulcio) to the latest version.

Get the container digest:

```shell
crane digest ghcr.io/sigstore/fulcio:v1.2.3 # Specify version
```

Update `charts/fulcio/values.yaml` with the new container version and digest.

Update `charts/fulcio/Chart.yaml`, bumping `version`, `appVersion`, and the image reference.

Run `helm-docs -g charts/fulcio` to update the README.

Create a PR and wait for an oncall engineer to approve and merge.

Afterwards, update the [scaffold](https://github.com/sigstore/helm-charts/tree/main/charts/scaffold)
chart with the bumped Fulcio chart version.

An oncall engineer also needs to update the scaffold chart version on the PGI repo.

## Announcements

1. Post on the `#general` and `#fulcio` Slack channels.
2. If it's a significant release, send an announcement email to `sigstore-dev@googlegroups.com` mailing list.
