# Release

This directory contain the files and scripts to run a cosign release.

# Cutting a Fulcio Release [workflow]

1. Release notes: Create a PR to update and review release notes in CHANGELOG.md.
  - Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.

  You can get a list of pull requests since the last release by substituting in the date of the last release and running:

	```
	git log --pretty="* %s" --after="YYYY-MM-DD"
	```
	
	and a list of authors by running:
	
	```
	git log --pretty="* %an" --after="YYYY-MM-DD" | sort -u
	```

2. Run "Cut Release" workflow
	- Open the "Actions" screen
	- Select the "Cut Release" workflow under "Workflows" on the left
	- Click on the "Run workflow" drop down button to the right
	- Fill in the required fields
		- release_tag
		- key_ring
		- key_name
	- Click on "Run workflow"

3. Publish Release
	- Find the draft release on the "Releases" page; [link](https://github.com/sigstore/fulcio/releases)
		- Click on "tags" link on the Code tab.
	 	- Click on "Releases" toggle.
	- Click on the edit icon for the draft release
	- Update release notes
	- Click "Publish release"  

## OIDC for Github Actions

One time setup in ./hack/github-oidc-setup.sh. This is to provide GitHub actions access to kick off gcloud builds.

# Cutting a Fulcio Release [manual]

1. Release notes: Create a PR to update and review release notes in CHANGELOG.md.
  - Check merged pull requests since the last release and make sure enhancements, bug fixes, and authors are reflected in the notes.

	You can get a list of pull requests since the last release by substituting in the date of the last release and running:
	
	```
	git log --pretty="* %s" --after="YYYY-MM-DD"
	```
	
	and a list of authors by running:
	
	```
	git log --pretty="* %an" --after="YYYY-MM-DD" | sort -u
	```

2. Tag the repository

	```shell
	$ export RELEASE_TAG=<release version, eg "v1.1.0">
	$ git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
	$ git push origin ${RELEASE_TAG}
	```

3. Submit the cloudbuild Job using the following command:

	```shell
	$ gcloud builds submit --config <PATH_TO_CLOUDBUILD> \
	   --substitutions _GIT_TAG=<_GIT_TAG>,_TOOL_ORG=sigstore,_TOOL_REPO=fulcio,_STORAGE_LOCATION=fulcio-releases,_KEY_RING=<KEY_RING>,_KEY_NAME=<KEY_NAME>,_GITHUB_USER=<GITHUB_USER> \
	   --project <GCP_PROJECT>
	```
	
	Where:
	
	- `PATH_TO_CLOUDBUILD` is the path where the cloudbuild.yaml can be found.
	- `GCP_PROJECT` is the GCP project where we will run the job.
	- `_GIT_TAG` is the release version we are publishing, this will also create the GitHub Tag.
	- `_TOOL_ORG` is the GitHub Org we will use. Default `sigstore`.
	- `_TOOL_REPO` is the repository we will use to clone. Default `cosign`.
	- `_STORAGE_LOCATION` where to push the built artifacts. Default `cosign-releases`.
	- `_KEY_RING` key ring name of your cosign key.
	- `_KEY_NAME` key name of your  cosign key.
	- `_KEY_VERSION` version of the key storaged in KMS. Default `1`.
	- `_KEY_LOCATION` location in GCP where the key is storaged. Default `global`.
	- `_GITHUB_USER` GitHub user to authenticate for pushing to GHCR.

4. When the job finish, whithout issues, you should be able to see in GitHub a draft release.
You now can review the release, make any changes if needed and then publish to make it an official release.

5. Send an annoucement email to `sigstore-dev@googlegroups.com` mailling list

6. Tweet about the new release with a fun new trigonometry pun!

7. Honk!

#### After the release:

* Add a pending new section in CHANGELOG.md to set up for the next release
* Create a new GitHub Milestone
