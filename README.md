# Synopsis

TrustedCerts Kubernetes Operator
API Status: v1alpha1

Distributes trusted x.509 certificate authority (CA) certificates from one or more
sources, to one or more destinations -- based on custom resources.

# Documentation

See ```examples/``` for example CRs.

Installation is provided via Loftsman/Helm. See ```kubernetes/``` 
for chart(s).

# Tests

Test coverage is currently minimal, consisting of 
scaffolded tests from the Operator SDK Generation. 

Tests are executed as part of multi-stage Dockerfile build,
along with vetting and linting. Tests can also be executed
via ```make test```.

# Contributors

This operator was scaffolded+ using the Operator SDK:

```
# operator-sdk version
operator-sdk version: "v1.0.1", 
commit: "4169b318b578156ed56530f373d328276d040a1b", 
kubernetes version: "v1.18.2", 
go version: "go1.13.15 linux/amd64", 
GOOS: "linux", 
GOARCH: "amd64"
```

The ```Makefile``` was also customized, from this scaffolding
and continues to function, for local development. 

An explanation for the ```Makefile``` steps can be found in (mostly)
in the Operator SDK Golang Tutorial and related links.

The ```developer-build.sh``` and ```developer-clean.sh``` scripts
are provided as conveniences to iterate over build, deploy, and 
clean-up against at kubernetes cluster. 

Note that the chart contents (crds, templates) are not currently 
automatically pulled into the chart as a result of using the Makefile.

# License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Resources/References

https://github.com/operator-framework/operator-sdk
