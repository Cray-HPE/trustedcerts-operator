
# Verifying Tekton Pipeline 

This readme walks through the steps to verify the pipeline defined in [tekton](../tekton/go/pipeline.yaml) 

1. Verify Signature infrastructure
2. Verify Signed Container image with Cosign via tekton chains
3. Verify Build Provenance for Tekton Steps
4. Verify Trivy scan results 
5. Verify SBOM attestations 

## Fulcio and Rekor

Fulcio URL: http://$REKOR_ENDPOINT

Rekor URL: http://$FULCIO_ENDPOINT

Each piece generates keys and certificates that are needed for signing and verifying.

- Cosign: Requires the fulcio root cert, the ct log public key, and the rekor public key 
- Rekor: Rekor key pair is in [GCP oci-signer-service-dev KMS](https://console.cloud.google.com/security/kms/keyring/manage/global/rekor-keyring/key?project=oci-signer-service-dev)
- Chains: Requires fulcio and rekor URL endpoint 
- CTLog: CT Log public and private keys are in [GCP secrets manager](https://console.cloud.google.com/security/secret-manager/secret/ctlog-public-key/versions?project=oci-signer-service-dev)
- Fulcio Cert: Available in Fulcio endpoint $FULCIO_ENDPOINT/api/v1/rootCert or in the [GCP Secrets Manager](https://console.cloud.google.com/security/secret-manager/secret/fulcio-root-ca/versions?project=oci-signer-service-dev)

fulcio.crt.pem
```
cat <<EOF > fulcio.crt.pem
-----BEGIN CERTIFICATE-----
MIIB9TCCAXygAwIBAgIUAPZMASHe36cox0zX6kJA9c/j6vUwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTkxOTA3NTZaFw0zMjA0MTYxOTA3NTVaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR+
LkzqeXhe0LDKGM4N40Dj5x/qDsPPJ1sHd4TUgzQnAh0SPiHZimYZwg+oDiV1iVAV
ySoTgnc+M3LQ3DvF7ZaP8zoGWXe/TxIs1SFNn7sjelMSbAhhAbr94/rd8FV8bJGj
YzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTO
gi85M7PvyKumMWIMAuSTuSZGZDAfBgNVHSMEGDAWgBTOgi85M7PvyKumMWIMAuST
uSZGZDAKBggqhkjOPQQDAwNnADBkAjBrYlhsh55Cw2Yfyp+0dn1SyUwvv+k7uSsK
dAj0UjMYKa2/0awiHkB5fhs+qhyyQfgCMFSVP5GqFct7Tu4vJ6GeCBHqEG/b0wBB
0jIAd8OCHWlNZhhXWs8wbpHHd4W9NThIdw==
-----END CERTIFICATE-----
EOF
```
ctlog.pub
```
cat <<EOF > ctlog.pub
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEApPMWGQvinGvBnbnCpQYxasxzqVWzJp3G3RE12wy/GSvZB6fzIL6Y
sdLvITvsIuMT0QMsSsNvmgXUsR+dOhOJPOKwsM+d/FOkeLfHRqqo/gOrc0Kv6iBN
5LDFalBwA9Chy3Wv7bETLpDEkFh/sPqCJxLkC8YRJCcMwgr4hXp6K5HrcD3lQ3NB
hJGzUcqvEfZPbLpX2Op0bYwF9qDjotQKsG0QzeVtOGEU0OCRpyKE7VdNCta42NkV
lCW688klcAJdb2zHGcfjw0xH37zTSCpaxAGkRpiXY5eo9nlEZxdaqE4pVC7MSPpL
5PSMkP83ZsyFdR4EuViSOKNcngD11+ypAoFZB7y9dZW0j4NbHvGfvfFFBYWl0Zc6
TC9r/CZGWJaWnBpG+hBIYlbi+IW/iBNB+xYTJHq3jbTCuGMQY1evhq0jmeokVMbC
dsGAQMYlXB5nvsb//gDerpMGsdgf2FmQjg+zW7OjoNE8mfTghe/GeT+Bd1BK5lUG
SvRaQ2YRGxHwdKjkldxg5D8bdgmksIr1j6TIYmhF2ID3WWu01/UBLTOxCR6I9nvR
Wvzp6CY2CrrIj6mvgg3aFqzHgCbhegoBQ/BGfGBEQJ5la8VGeSjamSU56wf+u/N1
5aUdk3V1zdsOyayUlSeYXIWTjmsNs3/puqX055eEQfAD3bZIu9vzmTcCAwEAAQ==
-----END RSA PUBLIC KEY-----
EOF
```
rekor.pub
```
cat <<EOF > rekor.pub
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeaitqbd1eWtvyMOKt5ai+GyCLtJj
zEOokp7xwTGgbdnLrUOcArYtnrS5iTnjVHiP/QzN1ztgCrA28+dbyKf2RQ==
-----END PUBLIC KEY-----
EOF
```

## Verifying Signing infrastracture

Here we can verify the signing infrastructure is working as expected

```bash
export FULCIO_URL=http://$FULCIO_IP_ADDRESS
export REKOR_URL=http://$REKOR_IP_ADDRESS
export IMAGE=gcr.io/oci-tekton-service-dev/trustedcert-operator/manager@sha256:79eab90bf94f0e6490de9fd1abe002c6897573902c72f79c869748fc24647e2e
```

Using rekor-cli:

```shell
rekor-cli --rekor_server ${REKOR_URL} loginfo
```
```
Consistency proof valid!
Verification Successful!
Tree Size: 620
Root Hash: e087ffb646ccf391ee60d330ba900cfb30f133aaa0868388476749d8acb595eb
Timestamp: 2022-06-30T16:11:07Z
```

With Chains signing each tekton task output, there are numerous entries in the log

## Verifying Container Signature with Cosign

```bash
export COSIGN_EXPERIMENTAL=1
export SIGSTORE_ROOT_FILE=$(pwd)/fulcio.crt.pem
export SIGSTORE_REKOR_PUBLIC_KEY=$(pwd)/rekor.pub 
cosign verify --rekor-url $REKOR_URL $IMAGE | jq -r .
```

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "gcr.io/oci-tekton-service-dev/trustedcert-operator/manager"
      },
      "image": {
        "docker-manifest-digest": "sha256:79eab90bf94f0e6490de9fd1abe002c6897573902c72f79c869748fc24647e2e"
      },
      "type": "cosign container image signature"
    },
    "optional": {
      "Issuer": "https://sig-spire.algol60.net",
      "Subject": "spiffe://sig-spire.algol60.net/ns/tekton-chains/sa/tekton-chains-controller"
    }
  }
]

```

## Verifying Build Provenance

Verify the Tekton Chains by choosing one of the steps. We can do this for any of the taskruns, but let's do the one
that does the build. Tekton stores this information in the Taskrun annotations, so let's pull out the transparency entry.

```shell
tkn pipelinerun describe trusted-cert-pipeline-run-lfb88
```

```shell
Name:              trusted-cert-pipeline-run-lfb88
Namespace:         default
Pipeline Ref:      trusted-cert-build-pipeline
Service Account:   tekton-sa
Timeout:           1h0m0s
Labels:
 tekton.dev/pipeline=trusted-cert-build-pipeline

Status

STARTED          DURATION     STATUS
15 minutes ago   13 minutes   Succeeded

Params

 NAME                              VALUE
 GIT_URL                           https://github.com/strongjz/trustedcerts-operator.git
 APPLICATION                       trustedcerts-operator
 OUTPUT                            manager
 TARGET                            ./cmd/manager/
 GIT_REVISION                      tekton
 IMAGE                             gcr.io/oci-tekton-service-dev/trustedcert-operator
 DOCKERFILE                        source/Dockerfile-token
 CONTEXT                           ./source
 SIGSTORE_CT_LOG_PUBLIC_KEY_FILE   /data/ctlog-public.pem
 COSIGN_REPOSITORY                 gcr.io/oci-tekton-service-dev/trustedcert-operator/manager
 FULCIO_ENDPOINT                   http://fulcio.default.svc.cluster.local
 REKOR_ENDPOINT                    http://rekor.default.svc.cluster.local

Workspaces

 NAME            SUB PATH   WORKSPACE BINDING
 source          ---        PersistentVolumeClaim (claimName=trusted-cert-source)
 kaniko-secret   ---        Secret (secret=kaniko-secret)
 dockerconfig    ---        Secret (secret=registry-credentials)
 dependencies    ---        PersistentVolumeClaim (claimName=trusted-cert-deps)

Taskruns

 NAME                                                   TASK NAME              STARTED          DURATION     STATUS
 trusted-cert-pipeline-run-lfb88-sbom                   sbom                   2 minutes ago    12 seconds   Succeeded
 trusted-cert-pipeline-run-lfb88-trivy-scan             trivy-scan             2 minutes ago    13 seconds   Succeeded
 trusted-cert-pipeline-run-lfb88-source-to-image        source-to-image        13 minutes ago   11 minutes   Succeeded
 trusted-cert-pipeline-run-lfb88-go-build               go-build               15 minutes ago   1 minute     Succeeded
 trusted-cert-pipeline-run-lfb88-install-dependencies   install-dependencies   15 minutes ago   27 seconds   Succeeded
 trusted-cert-pipeline-run-lfb88-fetch-from-git         fetch-from-git         15 minutes ago   28 seconds   Succeeded

```

Export the Container build image task run name 

```shell
export BUILD_TASK_NAME=trusted-cert-pipeline-run-lfb88-go-build
```
Chains will annotate the task run with the Rekor transparency log id 

```shell
kubectl get taskruns $BUILD_TASK_NAME -ojsonpath='{.metadata.annotations.chains\.tekton\.dev/transparency}'
```

This should print something similar to the following.

```
http://$FULCIO_IP_ADDRESS/api/v1/log/entries?logIndex=700
```

We can then fetch the corresponding entry from the Rekor log with:

```shell
TRANSPARENCY_INDEX=$(kubectl get taskruns $BUILD_TASK_NAME -ojsonpath='{.metadata.annotations.chains\.tekton\.dev/transparency}' | awk -F "=" '{print $2}')
rekor-cli --rekor_server $REKOR_URL get --log-index $TRANSPARENCY_INDEX --format json | jq -r .
```

The above should print something like this:

```shell
{
  "Attestation": "{\"_type\":\"https://in-toto.io/Statement/v0.1\",\"predicateType\":\"https://slsa.dev/provenance/v0.2\",\"subject\":null,\"predicate\":{\"builder\":{\"id\":\"https://tekton.dev/chains/v2\"},\"buildType\":\"https://tekton.dev/attestations/chains@v2\",\"invocation\":{\"configSource\":{},\"parameters\":{\"OUTPUT\":\"{string manager []}\",\"TARGET\":\"{string ./cmd/manager/ []}\"}},\"buildConfig\":{\"steps\":[{\"entryPoint\":\"cd $(workspaces.source.path)/source/\\n\\nexport CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on\\n\\n# Vet\\necho \\\"Running Go Vet\\\" \\ngo vet -mod=\\\"vendor\\\" ./cmd/... ./internal/...\\n\",\"arguments\":null,\"environment\":{\"container\":\"go-vet\",\"image\":\"gcr.io/oci-tekton-service-dev/go-build@sha256:cbd0be55e546204d5375f81a587df9006c9def6067dc55cdc7c907781911c3fb\"},\"annotations\":null},{\"entryPoint\":\"cd $(workspaces.source.path)/source/\\n\\nexport CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on\\n # Lint\\necho \\\"Running Go Lint\\\" \\n./util/golint -set_exit_status ./cmd/... ./internal/...\\n\",\"arguments\":null,\"environment\":{\"container\":\"go-lint\",\"image\":\"gcr.io/oci-tekton-service-dev/go-build@sha256:cbd0be55e546204d5375f81a587df9006c9def6067dc55cdc7c907781911c3fb\"},\"annotations\":null},{\"entryPoint\":\"cd $(workspaces.source.path)/source/\\nls -lah\\nexport CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on\\n# Build\\necho \\\"Running Go Build of $(params.OUTPUT) $(params.TARGET)\\\" \\ngo build -mod=\\\"vendor\\\" -a -o $(params.OUTPUT) $(params.TARGET)\\n\",\"arguments\":null,\"environment\":{\"container\":\"go-build\",\"image\":\"gcr.io/oci-tekton-service-dev/go-build@sha256:cbd0be55e546204d5375f81a587df9006c9def6067dc55cdc7c907781911c3fb\"},\"annotations\":null}]},\"metadata\":{\"buildStartedOn\":\"2022-07-01T20:37:39Z\",\"buildFinishedOn\":\"2022-07-01T20:39:14Z\",\"completeness\":{\"parameters\":false,\"environment\":false,\"materials\":false},\"reproducible\":false}}}",
  "AttestationType": "",
  "Body": {
    "IntotoObj": {
      "content": {
        "hash": {
          "algorithm": "sha256",
          "value": "4d9772519251dac10ea5f9400da946046192e8678100eab09170f1ef5a3db88a"
        }
      },
      "publicKey": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNTakNDQWRDZ0F3SUJBZ0lUS3lmMmowVkdFWlBCK1pzZmx6bnBXSlY0dFRBS0JnZ3Foa2pPUFFRREF6QXEKTVJVd0V3WURWUVFLRXd4emFXZHpkRzl5WlM1a1pYWXhFVEFQQmdOVkJBTVRDSE5wWjNOMGIzSmxNQjRYRFRJeQpNRGN3TVRJd016a3hORm9YRFRJeU1EY3dNVEl3TkRreE0xb3dBREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5CkF3RUhBMElBQkdMbVJKK0Z6eTBiMHFLLzdWTkRYUkU3ZHFQOGgwL3RVK3ROc0NVRVFvbjhROEM5U3VoVitnd0QKMG1lUU90dFR2T00yTlFQblhDb05nTUV6NVRhMFFyV2pnZjR3Z2Zzd0RnWURWUjBQQVFIL0JBUURBZ2VBTUJNRwpBMVVkSlFRTU1Bb0dDQ3NHQVFVRkJ3TURNQXdHQTFVZEV3RUIvd1FDTUFBd0hRWURWUjBPQkJZRUZHa3l1SDFmCjZiMEpwUE50dGVOVENsNmNhWTlwTUI4R0ExVWRJd1FZTUJhQUZNNkNMemt6cysvSXE2WXhZZ3dDNUpPNUprWmsKTUZrR0ExVWRFUUVCL3dSUE1FMkdTM053YVdabVpUb3ZMM05wWnkxemNHbHlaUzVoYkdkdmJEWXdMbTVsZEM5dQpjeTkwWld0MGIyNHRZMmhoYVc1ekwzTmhMM1JsYTNSdmJpMWphR0ZwYm5NdFkyOXVkSEp2Ykd4bGNqQXJCZ29yCkJnRUVBWU8vTUFFQkJCMW9kSFJ3Y3pvdkwzTnBaeTF6Y0dseVpTNWhiR2R2YkRZd0xtNWxkREFLQmdncWhrak8KUFFRREF3Tm9BREJsQWpFQW9Gd1FIMzZrc1FkOWt3NENVOTNHNWNXZ01WeVVTczdweVE0V0pKcmhvdjZTNWtjTApkeDY5Vll6bG16aVRrUTdQQWpCTWMxNGpDbmxwSWlTSmdQdUIwTGlnNDNLTVpTR2NwMTVZTS9GaEVaZXhGUFZBCmpFaDJZY1BRQzlTSU1CendadWc9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
    }
  },
  "LogIndex": 700,
  "IntegratedTime": 1656707954,
  "UUID": "201b4a0086985118df9de9312b14ebe1fa38c8fc9c32aef60d88eb229de8d1eb",
  "LogID": "ca16a87630334fd49ac535d11fc2c226ac9e3d781a934b7d3b4b0c4faa3a447c"
}

```

Chains also adds the signature and payload to annotations of a taskrun, and you can pull them out like this:

```bash
rekor-cli --rekor_server $REKOR_URL get --log-index $TRANSPARENCY_INDEX --format json | jq -r .Body.IntotoObj.publicKey | base64 -d | openssl x509 -noout -text -extensions subjectAltName | grep "Subject Alternative Name" -A3
```
Output
```bash
   X509v3 Subject Alternative Name: critical
                URI:spiffe://sig-spire.algol60.net/ns/tekton-chains/sa/tekton-chains-controller
            1.3.6.1.4.1.57264.1.1: 
                https://sig-spire.algol60.net

```

We see that the cert was requested from Fulcio, using the spire SVID for the tekton SA ` URI:spiffe://sig-spire.algol60.net/ns/tekton-chains/sa/tekton-chains-controller`

## Verify Trivy Scan 

Get the Task Run for the Trivy Scans
```shell
export BUILD_TASK_NAME=trusted-cert-pipeline-run-lfb88-trivy-scan
```

```shell
kubectl logs $BUILD_TASK_NAME-pod -c step-publish-scan-results
```

This should print something similar to the following.

```
$ kubectl logs $BUILD_TASK_NAME-pod -c step-publish-scan-results

Generating ephemeral keys...
Retrieving signed certificate...

        Note that there may be personally identifiable information associated with this signed artifact.
        This may include the email address associated with the account with which you authenticate.
        This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later.
**Warning** Using a non-standard public key for verifying SCT: /data/ctlog-public.pem
Successfully verified SCT...
Using payload from: /workspace/image.trivy
tlog entry created with index: 704
```

```shell
TRANSPARENCY_INDEX=704
rekor-cli --rekor_server $REKOR_URL get --log-index $TRANSPARENCY_INDEX --format json | jq -r .
```

We can see that cosign uploads the trivy scans data 

```bash
export COSIGN_EXPERIMENTAL=1
export SIGSTORE_ROOT_FILE=$(pwd)/fulcio.crt.pem
export SIGSTORE_REKOR_PUBLIC_KEY=$(pwd)/rekor.pub 
cosign verify-attestation $IMAGE | jq -r .payload | base64 -d | jq -r .predicate.Data | jq -r .
```

Trivy scan output 

<details>

```bash
rekor-cli --rekor_server $REKOR_URL get --log-index $TRANSPARENCY_INDEX --format json | jq -r .Attestation | jq -r .predicate.Data 
{
  "SchemaVersion": 2,
  "ArtifactName": "gcr.io/oci-tekton-service-dev/trustedcert-operator@sha256:2901fbae67d19c6dee0406dbc1b423bffd7233ff16b897a94da32dc94766966a",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "alpine",
      "Name": "3.16"
    },
    "ImageID": "sha256:1bbcef1ad2d493100ce38fef87f0c6ac3b828fdb3e9880e5328533719cd71a06",
    "DiffIDs": [
      "sha256:f7b9eb215cd780aaed40240044e4eceb90bf181669342883a53b59537b6e5381",
      "sha256:2c11fb6a43b9ed530d52a5315883a693068b9618f7703063f9c1311eec8e154e",
      "sha256:d7f771365c258b1715e1c9a56e5a4311ba360028af95f8d764009947ddb95ebc"
    ],
    "RepoDigests": [
      "gcr.io/oci-tekton-service-dev/trustedcert-operator@sha256:2901fbae67d19c6dee0406dbc1b423bffd7233ff16b897a94da32dc94766966a"
    ],
    "ImageConfig": {
      "architecture": "amd64",
      "author": "github.com/chainguard-dev/apko",
      "created": "2022-07-01T20:50:22.526339003Z",
      "history": [
        {
          "author": "apko",
          "created": "2022-06-29T00:23:02Z",
          "created_by": "apko",
          "comment": "This is an apko single-layer image"
        },
        {
          "author": "kaniko",
          "created": "0001-01-01T00:00:00Z",
          "created_by": "COPY manager ."
        },
        {
          "author": "kaniko",
          "created": "0001-01-01T00:00:00Z",
          "created_by": "RUN addgroup -S nonroot && adduser -S nonroot -G nonroot"
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:f7b9eb215cd780aaed40240044e4eceb90bf181669342883a53b59537b6e5381",
          "sha256:2c11fb6a43b9ed530d52a5315883a693068b9618f7703063f9c1311eec8e154e",
          "sha256:d7f771365c258b1715e1c9a56e5a4311ba360028af95f8d764009947ddb95ebc"
        ]
      },
      "config": {
        "Entrypoint": [
          "/manager"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
        ],
        "User": "nonroot:nonroot",
        "WorkingDir": "/"
      }
    }
  },
  "Results": [
    {
      "Target": "gcr.io/oci-tekton-service-dev/trustedcert-operator@sha256:2901fbae67d19c6dee0406dbc1b423bffd7233ff16b897a94da32dc94766966a (alpine 3.16)",
      "Class": "os-pkgs",
      "Type": "alpine"
    },
    {
      "Target": "manager",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-3121",
          "PkgName": "github.com/gogo/protobuf",
          "InstalledVersion": "v1.3.1",
          "FixedVersion": "1.3.2",
          "Layer": {
            "Digest": "sha256:f1be3a5ed78cbb597c34cded16a0b0fe3e9204f795a2a38e904fd2e295b71840",
            "DiffID": "sha256:2c11fb6a43b9ed530d52a5315883a693068b9618f7703063f9c1311eec8e154e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-3121",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "gogo/protobuf: plugin/unmarshal/unmarshal.go lacks certain index validation",
          "Description": "An issue was discovered in GoGo Protobuf before 1.3.2. plugin/unmarshal/unmarshal.go lacks certain index validation, aka the \"skippy peanut butter\" issue.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-129"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
              "V2Score": 7.5,
              "V3Score": 8.6
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 8.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-3121",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3121",
            "https://discuss.hashicorp.com/t/hcsec-2021-23-consul-exposed-to-denial-of-service-in-gogo-protobuf-dependency/29025",
            "https://github.com/gogo/protobuf/commit/b03c65ea87cdc3521ede29f62fe3ce239267c1bc",
            "https://github.com/gogo/protobuf/compare/v1.3.1...v1.3.2",
            "https://lists.apache.org/thread.html/r68032132c0399c29d6cdc7bd44918535da54060a10a12b1591328bff@%3Cnotifications.skywalking.apache.org%3E",
            "https://lists.apache.org/thread.html/r88d69555cb74a129a7bf84838073b61259b4a3830190e05a3b87994e@%3Ccommits.pulsar.apache.org%3E",
            "https://lists.apache.org/thread.html/rc1e9ff22c5641d73701ba56362fb867d40ed287cca000b131dcf4a44@%3Ccommits.pulsar.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3121",
            "https://pkg.go.dev/vuln/GO-2021-0053",
            "https://security.netapp.com/advisory/ntap-20210219-0006/"
          ],
          "PublishedDate": "2021-01-11T06:15:00Z",
          "LastModifiedDate": "2022-04-01T15:41:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-38561",
          "PkgName": "golang.org/x/text",
          "InstalledVersion": "v0.3.3",
          "FixedVersion": "0.3.7",
          "Layer": {
            "Digest": "sha256:f1be3a5ed78cbb597c34cded16a0b0fe3e9204f795a2a38e904fd2e295b71840",
            "DiffID": "sha256:2c11fb6a43b9ed530d52a5315883a693068b9618f7703063f9c1311eec8e154e"
          },
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-38561",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "golang: out-of-bounds read in golang.org/x/text/language leads to DoS",
          "Description": "No description is available for this CVE.",
          "Severity": "HIGH",
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-38561",
            "https://go.dev/cl/340830",
            "https://go.googlesource.com/text/+/383b2e75a7a4198c42f8f87833eefb772868a56f",
            "https://pkg.go.dev/vuln/GO-2021-0113"
          ]
        },
        {
          "VulnerabilityID": "CVE-2020-8565",
          "PkgName": "k8s.io/client-go",
          "InstalledVersion": "v0.18.6",
          "FixedVersion": "0.20.0-alpha.2",
          "Layer": {
            "Digest": "sha256:f1be3a5ed78cbb597c34cded16a0b0fe3e9204f795a2a38e904fd2e295b71840",
            "DiffID": "sha256:2c11fb6a43b9ed530d52a5315883a693068b9618f7703063f9c1311eec8e154e"
          },
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8565",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "kubernetes: Incomplete fix for CVE-2019-11250 allows for token leak in logs when logLevel >= 9",
          "Description": "In Kubernetes, if the logging level is set to at least 9, authorization and bearer tokens will be written to log files. This can occur both in API server logs and client tool output like kubectl. This affects <= v1.19.3, <= v1.18.10, <= v1.17.13, < v1.20.0-alpha2.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-532"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 2.1,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8565",
            "https://github.com/kubernetes/kubernetes/commit/e99df0e5a75eb6e86123b56d53e9b7ca0fd00419",
            "https://github.com/kubernetes/kubernetes/issues/95623",
            "https://github.com/kubernetes/kubernetes/pull/95316",
            "https://groups.google.com/g/kubernetes-announce/c/ScdmyORnPDk",
            "https://groups.google.com/g/kubernetes-security-discuss/c/vm-HcrFUOCs/m/36utxAM5CwAJ",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8565",
            "https://pkg.go.dev/vuln/GO-2021-0064"
          ],
          "PublishedDate": "2020-12-07T22:15:00Z",
          "LastModifiedDate": "2020-12-08T19:51:00Z"
        }
      ]
    }
  ]
}
```

</details>

## Verifying SBOM 

The SBOM is generated using [trivy sbom](https://aquasecurity.github.io/trivy/v0.27.1/docs/references/cli/sbom/) in the
sbom-generate task. 

Get the Task run for the SBOM from the Pipeline run 

The `publish-sbom` Step in Sbom task will have the rekor log entry `572` in this example

```bash
tkn tr logs trusted-cert-pipeline-run-lfb88-sbom  
```

```bash
[trivy-sbom] 2022-07-01T20:50:32.412Z	[34mINFO[0m	Need to update DB
[trivy-sbom] 2022-07-01T20:50:32.412Z	[34mINFO[0m	DB Repository: ghcr.io/aquasecurity/trivy-db
[trivy-sbom] 2022-07-01T20:50:32.412Z	[34mINFO[0m	Downloading DB...
[trivy-sbom] 2022-07-01T20:50:35.182Z	[34mINFO[0m	Detected OS: alpine
[trivy-sbom] 2022-07-01T20:50:35.182Z	[34mINFO[0m	This OS version is not on the EOL list: alpine 3.16
[trivy-sbom] 2022-07-01T20:50:35.182Z	[34mINFO[0m	Detecting Alpine vulnerabilities...
[trivy-sbom] 2022-07-01T20:50:35.184Z	[34mINFO[0m	Number of language-specific files: 1
[trivy-sbom] 2022-07-01T20:50:35.184Z	[34mINFO[0m	Detecting gobinary vulnerabilities...
[trivy-sbom] 26.59 MiB / 32.84 MiB [------------------------------------------------->___________] 80.96% ? p/s ?32.84 MiB / 32.84 MiB [----------------------------------------------------------->] 100.00% ? p/s ?32.84 MiB / 32.84 MiB [----------------------------------------------------------->] 100.00% ? p/s ?32.84 MiB / 32.84 MiB [---------------------------------------------->] 100.00% 10.42 MiB p/s ETA 0s32.84 MiB / 32.84 MiB [---------------------------------------------->] 100.00% 10.42 MiB p/s ETA 0s32.84 MiB / 32.84 MiB [---------------------------------------------->] 100.00% 10.42 MiB p/s ETA 0s32.84 MiB / 32.84 MiB [-------------------------------------------------] 100.00% 27.53 MiB p/s 1.4s

[publish-sbom] Generating ephemeral keys...
[publish-sbom] Retrieving signed certificate...
[publish-sbom] 
[publish-sbom]         Note that there may be personally identifiable information associated with this signed artifact.
[publish-sbom]         This may include the email address associated with the account with which you authenticate.
[publish-sbom]         This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later.
[publish-sbom] **Warning** Using a non-standard public key for verifying SCT: /data/ctlog-public.pem
[publish-sbom] Successfully verified SCT...
[publish-sbom] Using payload from: /workspace/image.sbom
[publish-sbom] tlog entry created with index: 703

```

Retrieve the log entry from Rekor

```shell
rekor-cli --rekor_server $REKOR_URL get --log-index 703 --format json | jq -r .Attestation | jq -r .predicate.Data
```

SBOM output 

<details>

```bash
SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: gcr.io/oci-tekton-service-dev/trustedcert-operator@sha256:2901fbae67d19c6dee0406dbc1b423bffd7233ff16b897a94da32dc94766966a
DocumentNamespace: http://aquasecurity.github.io/trivy/container_image/gcr.io/oci-tekton-service-dev/trustedcert-operator@sha256:2901fbae67d19c6dee0406dbc1b423bffd7233ff16b897a94da32dc94766966a-79324462-85a5-470e-acb2-78edd16c9a16
Creator: Organization: aquasecurity
Creator: Tool: trivy
Created: 2022-07-01T20:50:35.187473511Z

##### Package: alpine-baselayout-data

PackageName: alpine-baselayout-data
SPDXID: SPDXRef-13f7b2cca559a43c
PackageVersion: 3.2.0-r23
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: google.golang.org/protobuf

PackageName: google.golang.org/protobuf
SPDXID: SPDXRef-158383bdde1f10d1
PackageVersion: v1.23.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/gogo/protobuf

PackageName: github.com/gogo/protobuf
SPDXID: SPDXRef-22bf8b948543dce7
PackageVersion: v1.3.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/qri-io/jsonschema

PackageName: github.com/qri-io/jsonschema
SPDXID: SPDXRef-245cfe86001c4789
PackageVersion: v0.2.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/hashicorp/golang-lru

PackageName: github.com/hashicorp/golang-lru
SPDXID: SPDXRef-2c6a4cd8b5a0e22
PackageVersion: v0.5.4
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/pkg/errors

PackageName: github.com/pkg/errors
SPDXID: SPDXRef-310752320eef0212
PackageVersion: v0.8.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: sigs.k8s.io/yaml

PackageName: sigs.k8s.io/yaml
SPDXID: SPDXRef-314df8b72eb2e812
PackageVersion: v1.2.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: k8s.io/client-go

PackageName: k8s.io/client-go
SPDXID: SPDXRef-3266e9f5364ce8cb
PackageVersion: v0.18.6
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: k8s.io/kube-openapi

PackageName: k8s.io/kube-openapi
SPDXID: SPDXRef-38bab78aac6c625e
PackageVersion: v0.0.0-20200410145947-61e04a5be9a6
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/google/go-cmp

PackageName: github.com/google/go-cmp
SPDXID: SPDXRef-390f34b3309656
PackageVersion: v0.4.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: go.uber.org/zap

PackageName: go.uber.org/zap
SPDXID: SPDXRef-4025a4a8fdde3ae3
PackageVersion: v1.10.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/matttproud/golang_protobuf_extensions

PackageName: github.com/matttproud/golang_protobuf_extensions
SPDXID: SPDXRef-43c52bece55678cc
PackageVersion: v1.0.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: alpine-conf

PackageName: alpine-conf
SPDXID: SPDXRef-44cf505c22b84daa
PackageVersion: 3.14.2-r0
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: musl-utils

PackageName: musl-utils
SPDXID: SPDXRef-4620d6d251f46e90
PackageVersion: 1.2.3-r0
FilesAnalyzed: false
PackageLicenseConcluded: MIT BSD GPL2+
PackageLicenseDeclared: MIT BSD GPL2+

##### Package: golang.org/x/sys

PackageName: golang.org/x/sys
SPDXID: SPDXRef-48274543df516f32
PackageVersion: v0.0.0-20200323222414-85ca7c5b95cd
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: libc-utils

PackageName: libc-utils
SPDXID: SPDXRef-498b4ae7619d7015
PackageVersion: 0.7.2-r3
FilesAnalyzed: false
PackageLicenseConcluded: BSD-2-Clause AND BSD-3-Clause
PackageLicenseDeclared: BSD-2-Clause AND BSD-3-Clause

##### Package: github.com/modern-go/reflect2

PackageName: github.com/modern-go/reflect2
SPDXID: SPDXRef-5001f37e0b2be172
PackageVersion: v1.0.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/prometheus/common

PackageName: github.com/prometheus/common
SPDXID: SPDXRef-532c571a1f8c8821
PackageVersion: v0.4.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/prometheus/client_model

PackageName: github.com/prometheus/client_model
SPDXID: SPDXRef-532e58415853ad98
PackageVersion: v0.2.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/davecgh/go-spew

PackageName: github.com/davecgh/go-spew
SPDXID: SPDXRef-58d28b440c28788a
PackageVersion: v1.1.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: gopkg.in/yaml.v2

PackageName: gopkg.in/yaml.v2
SPDXID: SPDXRef-59485d8086839adc
PackageVersion: v2.3.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: busybox-initscripts

PackageName: busybox-initscripts
SPDXID: SPDXRef-63e13a7640f5a105
PackageVersion: 4.1-r1
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: k8s.io/klog/v2

PackageName: k8s.io/klog/v2
SPDXID: SPDXRef-687ec47e5cb6d788
PackageVersion: v2.0.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/golang/groupcache

PackageName: github.com/golang/groupcache
SPDXID: SPDXRef-696441f643a337f0
PackageVersion: v0.0.0-20190129154638-5b532d6fd5ef
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/go-logr/zapr

PackageName: github.com/go-logr/zapr
SPDXID: SPDXRef-6b8d497fc7d17d8e
PackageVersion: v0.1.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: go.uber.org/multierr

PackageName: go.uber.org/multierr
SPDXID: SPDXRef-6e83c404c06369a6
PackageVersion: v1.1.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: k8s.io/utils

PackageName: k8s.io/utils
SPDXID: SPDXRef-70559564e1024836
PackageVersion: v0.0.0-20200603063816-c1c6865ac451
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: musl

PackageName: musl
SPDXID: SPDXRef-7bbd2f04f5b24d21
PackageVersion: 1.2.3-r0
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: github.com/go-logr/logr

PackageName: github.com/go-logr/logr
SPDXID: SPDXRef-7db6665baff6125a
PackageVersion: v0.1.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: golang.org/x/net

PackageName: golang.org/x/net
SPDXID: SPDXRef-7e45e26fe1c6d68d
PackageVersion: v0.0.0-20200520004742-59133d7f0dd7
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: golang.org/x/time

PackageName: golang.org/x/time
SPDXID: SPDXRef-7f8d0e258f585f05
PackageVersion: v0.0.0-20190308202827-9d24e82272b4
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/imdario/mergo

PackageName: github.com/imdario/mergo
SPDXID: SPDXRef-80792ddd01b71d1a
PackageVersion: v0.3.9
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/qri-io/jsonpointer

PackageName: github.com/qri-io/jsonpointer
SPDXID: SPDXRef-81f745695529f443
PackageVersion: v0.1.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: golang.org/x/text

PackageName: golang.org/x/text
SPDXID: SPDXRef-8cb1bf7a52bacb09
PackageVersion: v0.3.3
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/google/uuid

PackageName: github.com/google/uuid
SPDXID: SPDXRef-902376bb17a5bdcc
PackageVersion: v1.1.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: k8s.io/api

PackageName: k8s.io/api
SPDXID: SPDXRef-95e9d6bfaad9d707
PackageVersion: v0.18.6
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/googleapis/gnostic

PackageName: github.com/googleapis/gnostic
SPDXID: SPDXRef-970a9de8e697e106
PackageVersion: v0.3.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: sigs.k8s.io/structured-merge-diff/v3

PackageName: sigs.k8s.io/structured-merge-diff/v3
SPDXID: SPDXRef-9938602050648225
PackageVersion: v3.0.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: sigs.k8s.io/controller-runtime

PackageName: sigs.k8s.io/controller-runtime
SPDXID: SPDXRef-9a487f32266158e7
PackageVersion: v0.6.2
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/modern-go/concurrent

PackageName: github.com/modern-go/concurrent
SPDXID: SPDXRef-9a7f5a35710cea2b
PackageVersion: v0.0.0-20180306012644-bacd9c7ef1dd
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/evanphx/json-patch

PackageName: github.com/evanphx/json-patch
SPDXID: SPDXRef-9b64ad90618569c8
PackageVersion: v4.5.0+incompatible
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: ca-certificates-bundle

PackageName: ca-certificates-bundle
SPDXID: SPDXRef-9ed7585fa521454f
PackageVersion: 20211220-r0
FilesAnalyzed: false
PackageLicenseConcluded: MPL-2.0 AND MIT
PackageLicenseDeclared: MPL-2.0 AND MIT

##### Package: github.com/spf13/pflag

PackageName: github.com/spf13/pflag
SPDXID: SPDXRef-a1d281eb57e00645
PackageVersion: v1.0.5
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: k8s.io/apiextensions-apiserver

PackageName: k8s.io/apiextensions-apiserver
SPDXID: SPDXRef-a3f688eede21d069
PackageVersion: v0.18.6
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: busybox-ifupdown

PackageName: busybox-ifupdown
SPDXID: SPDXRef-a77f15cdf95bf33a
PackageVersion: 1.35.0-r17
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: gomodules.xyz/jsonpatch/v2

PackageName: gomodules.xyz/jsonpatch/v2
SPDXID: SPDXRef-a97f0a9d5ff5183
PackageVersion: v2.0.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: golang.org/x/crypto

PackageName: golang.org/x/crypto
SPDXID: SPDXRef-aa22118f435c2f4d
PackageVersion: v0.0.0-20200220183623-bac4c82f6975
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/prometheus/client_golang

PackageName: github.com/prometheus/client_golang
SPDXID: SPDXRef-abf087b57a107943
PackageVersion: v1.0.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: busybox

PackageName: busybox
SPDXID: SPDXRef-b24d4c16a3501c39
PackageVersion: 1.35.0-r17
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: busybox-suid

PackageName: busybox-suid
SPDXID: SPDXRef-b4a5ac75045c5f70
PackageVersion: 1.35.0-r17
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: libssl1.1

PackageName: libssl1.1
SPDXID: SPDXRef-b4d90348fc54ed58
PackageVersion: 1.1.1o-r0
FilesAnalyzed: false
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL

##### Package: github.com/fsnotify/fsnotify

PackageName: github.com/fsnotify/fsnotify
SPDXID: SPDXRef-b639b85205deadd8
PackageVersion: v1.4.9
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: alpine-baselayout

PackageName: alpine-baselayout
SPDXID: SPDXRef-b7388e3819d5378b
PackageVersion: 3.2.0-r23
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: cloud.google.com/go

PackageName: cloud.google.com/go
SPDXID: SPDXRef-c068238e642da212
PackageVersion: v0.38.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: ssl_client

PackageName: ssl_client
SPDXID: SPDXRef-c3b7741972e6c971
PackageVersion: 1.35.0-r17
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: mdev-conf

PackageName: mdev-conf
SPDXID: SPDXRef-c3baeb342f0c047b
PackageVersion: 4.1-r1
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: apk-tools

PackageName: apk-tools
SPDXID: SPDXRef-c56ecdb2d2ca2d73
PackageVersion: 2.12.9-r5
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: github.com/google/gofuzz

PackageName: github.com/google/gofuzz
SPDXID: SPDXRef-c6652623913959e
PackageVersion: v1.1.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: alpine-base

PackageName: alpine-base
SPDXID: SPDXRef-c6df72dee1131ff7
PackageVersion: 3.16.0-r0
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: k8s.io/klog

PackageName: k8s.io/klog
SPDXID: SPDXRef-ca4de44e7c6770ee
PackageVersion: v1.0.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: golang.org/x/oauth2

PackageName: golang.org/x/oauth2
SPDXID: SPDXRef-cd00356dac16becd
PackageVersion: v0.0.0-20190604053449-0f29369cfe45
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: libcrypto1.1

PackageName: libcrypto1.1
SPDXID: SPDXRef-d0b02ff7b77a69e7
PackageVersion: 1.1.1o-r0
FilesAnalyzed: false
PackageLicenseConcluded: OpenSSL
PackageLicenseDeclared: OpenSSL

##### Package: github.com/beorn7/perks

PackageName: github.com/beorn7/perks
SPDXID: SPDXRef-d7eacd8253d192bb
PackageVersion: v1.0.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: scanelf

PackageName: scanelf
SPDXID: SPDXRef-dac6a8b8894f6a54
PackageVersion: 1.3.4-r0
FilesAnalyzed: false
PackageLicenseConcluded: GPL-2.0-only
PackageLicenseDeclared: GPL-2.0-only

##### Package: github.com/prometheus/procfs

PackageName: github.com/prometheus/procfs
SPDXID: SPDXRef-e269e8e4e990888c
PackageVersion: v0.0.11
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: k8s.io/apimachinery

PackageName: k8s.io/apimachinery
SPDXID: SPDXRef-e41ef13eafdd3439
PackageVersion: v0.18.6
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: zlib

PackageName: zlib
SPDXID: SPDXRef-e4c6f30cd8e0f3d0
PackageVersion: 1.2.12-r1
FilesAnalyzed: false
PackageLicenseConcluded: Zlib
PackageLicenseDeclared: Zlib

##### Package: github.com/json-iterator/go

PackageName: github.com/json-iterator/go
SPDXID: SPDXRef-e67a5aa065a7c0a7
PackageVersion: v1.1.10
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: openrc

PackageName: openrc
SPDXID: SPDXRef-eb0f84746a18c381
PackageVersion: 0.44.10-r7
FilesAnalyzed: false
PackageLicenseConcluded: BSD-2-Clause
PackageLicenseDeclared: BSD-2-Clause

##### Package: alpine-keys

PackageName: alpine-keys
SPDXID: SPDXRef-eda385ad66bcd24e
PackageVersion: 2.4-r1
FilesAnalyzed: false
PackageLicenseConcluded: MIT
PackageLicenseDeclared: MIT

##### Package: go.uber.org/atomic

PackageName: go.uber.org/atomic
SPDXID: SPDXRef-ee61a168ea80f619
PackageVersion: v1.4.0
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: gopkg.in/inf.v0

PackageName: gopkg.in/inf.v0
SPDXID: SPDXRef-f8fb1b79d4dcf5d0
PackageVersion: v0.9.1
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE

##### Package: github.com/golang/protobuf

PackageName: github.com/golang/protobuf
SPDXID: SPDXRef-ffbdaed0db0f9939
PackageVersion: v1.4.2
FilesAnalyzed: false
PackageLicenseConcluded: NONE
PackageLicenseDeclared: NONE
```

</details>

Verify Signature of SBOM 

Verifying the Public Key from Fulcio requested by the Tekton SA 

```shell
rekor-cli --rekor_server $REKOR_URL get --log-index 703 --format json | jq -r .Body.IntotoObj.publicKey | base64 -d | openssl x509 -noout -text 
```
Output 

```bash
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            67:60:9d:f0:89:7a:63:82:f1:54:36:dc:9d:72:b8:4a:33:6e:43
    Signature Algorithm: ecdsa-with-SHA384
        Issuer: O=sigstore.dev, CN=sigstore
        Validity
            Not Before: Jul  1 20:50:35 2022 GMT
            Not After : Jul  1 21:00:34 2022 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:dc:83:03:b8:9b:a1:68:b0:1d:99:dd:e8:12:02:
                    4e:7d:d4:98:35:d0:b4:1c:22:9c:be:b1:b6:8b:0d:
                    c5:eb:f9:71:f5:e6:98:5b:79:0d:06:b4:09:12:f6:
                    64:d1:e9:67:91:76:26:2b:07:2a:d5:08:6a:ab:84:
                    62:56:65:0a:57
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                2B:CF:42:9B:FF:A0:A9:01:D5:30:9D:41:9D:CB:4F:F1:AB:41:E0:7C
            X509v3 Authority Key Identifier: 
                keyid:CE:82:2F:39:33:B3:EF:C8:AB:A6:31:62:0C:02:E4:93:B9:26:46:64

            X509v3 Subject Alternative Name: critical
                URI:https://kubernetes.io/namespaces/default/serviceaccounts/tekton-sa
            1.3.6.1.4.1.57264.1.1: 
                https://container.googleapis.com/v1/projects/oci-tekton-service-dev/locations/us-central1-a/clusters/tekton-dev
    Signature Algorithm: ecdsa-with-SHA384
         30:65:02:31:00:f7:39:ec:e8:35:94:78:b6:98:02:f3:87:41:
         a5:9c:69:de:26:aa:94:83:52:d5:a8:bd:5b:e6:b5:62:e0:ac:
         d0:8c:1e:2f:0c:bc:9a:98:99:22:8e:ef:2e:e7:5e:4d:a8:02:
         30:0f:a9:15:01:db:01:d5:e8:00:a7:89:15:74:a6:9b:33:1e:
         b9:83:44:1d:74:7e:63:0e:87:01:55:d1:94:64:2b:f6:5b:99:
         70:5a:23:e8:84:cf:05:11:10:d2:bb:03:cc
```
