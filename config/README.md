# GCP Project - Create a CA called "sigstore-test"

- Devops tier (faster)
- us-central1
- Strongest EC
- In UI, Go to policy, set max issuance to .138 Days :)

path should be: `--gcp_private_ca_parent=projects/project-rekor/locations/us-central1/certificateAuthorities/sigstore`

# Namespace

Let's run this in the `fulcio` namspace.

Create a new workloadidentity SA and worklaod binding:

```shell
$ gcloud iam service-accounts create fulcio

$ gcloud iam service-accounts add-iam-policy-binding   --role roles/iam.workloadIdentityUser   --member "serviceAccount:project-rekor.svc.id.goog[fulcio/default]"   fulcio@project-rekor.iam.gserviceaccount.com
```

Create namespace:

```shell
$ kubectl create ns fulcio-system
```

Annotate:

```
$ kubectl annotate serviceaccount \
  --namespace fulcio-system \
  default iam.gke.io/gcp-service-account=fulcio@project-rekor.iam.gserviceaccount.com
```

Test:

```
$ kubectl run -it --image google/cloud-sdk:slim \
  --serviceaccount default \
  --namespace fulcio-system \
  workload-identity-test

# gcloud auth list
Credentialed Accounts
ACTIVE  ACCOUNT
*       fulcio@project-rekor.iam.gserviceaccount.com
```

(Cleanup)

Give that service account cert rights.
CA : -> Add Member -> fulcio@project-rekor.iam.gserviceaccount.com -> Role -> CA Service -> Requestor

(TODO: create an intermediary, take this one offline)

# Debug

```shell
$ kubectl port-forward deployment/fulcio-server -n fulcio-system 5555:5555

$ kubectl logs -f deployment/fulcio-server -n fulcio
```
