#
# MIT License
#
# (C) Copyright 2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

set +x;

declare -a mandatory
mandatory=(
  GCP_PROJECT_ID
  POOL_NAME
  PROVIDER_NAME
  LOCATION
  REPO
  SERVICE_ACCOUNT_ID
  SERVICE_ACCOUNT
  PROJECT_NUMBER
)

for var in "${mandatory[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "Environment variable $var must be set"
    exit 1
  fi
done

if ! (gcloud iam workload-identity-pools describe "${POOL_NAME}" --location="${LOCATION}"); then
  gcloud iam workload-identity-pools create "${POOL_NAME}" \
    --project="${GCP_PROJECT_ID}" \
    --location="${LOCATION}" \
    --display-name="Github Actions Pool"
fi

if ! (gcloud iam workload-identity-pools providers describe "${PROVIDER_NAME}" --location="${LOCATION}" --workload-identity-pool="${POOL_NAME}"); then
  gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_NAME}" \
  --project="${GCP_PROJECT_ID}" \
  --location="${LOCATION}" \
  --workload-identity-pool="${POOL_NAME}" \
  --display-name="Trusted Cert Images" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.aud=assertion.aud,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"
fi

if ! (gcloud iam service-accounts describe "${SERVICE_ACCOUNT}"); then
gcloud iam service-accounts create "${SERVICE_ACCOUNT_ID}" \
  --description="Service account for TrustedCert Tekton Build" \
  --display-name="Github Actions for TrustedCert Tekton Build"
fi

# Adding binding is idempotent.
# For Workload Identity
gcloud iam service-accounts add-iam-policy-binding "${SERVICE_ACCOUNT}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/${LOCATION}/workloadIdentityPools/${POOL_NAME}/attribute.repository/${REPO}"

# For service account impersonation, used for managing groups.
gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/storage.admin" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"

# For pushing to GKE Cluster
gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/container.admin" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"

gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/compute.admin" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"


gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/iap.tunnelResourceAccessor" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"

gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"

gcloud iam service-accounts add-iam-policy-binding "${SERVICE_ACCOUNT}" \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:${GCP_PROJECT_ID}.svc.id.goog[${NAMESPACE}/${KSA_NAME}]"

gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/storage.objectAdmin" \
  --member="serviceAccount:${SERVICE_ACCOUNT}"

kubectl create serviceaccount "${KSA_NAME}" --namespace "${NAMESPACE}" || true

kubectl annotate serviceaccount "${KSA_NAME}" \
    --namespace "${NAMESPACE}" \
    iam.gke.io/gcp-service-account="${SERVICE_ACCOUNT}" || true
