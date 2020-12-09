#!/bin/bash

set -e 

version="$(cat .version)"

make generate
make manifests
make install
make docker-build IMG=trustedcerts-operator:v${version}
make deploy IMG=trustedcerts-operator:v${version}
