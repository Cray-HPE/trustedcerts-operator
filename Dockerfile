# Build the manager binary
FROM dtr.dev.cray.com/baseos/golang:1.14.9-alpine3.12 AS builder

RUN apk add make bash curl

WORKDIR /workspace

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

COPY cmd/ cmd/
COPY internal/ internal/
COPY vendor/ vendor/
COPY util/ util/
COPY Makefile Makefile

# Vet
RUN go vet -mod="vendor" ./cmd/... ./internal/...

# TODO: Integate test env from makefile
RUN make test

# Lint 
RUN ./util/golint -set_exit_status ./cmd/... ./internal/...

# Build
RUN go build -mod="vendor" -a -o manager ./cmd/manager/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM dtr.dev.cray.com/cache/gct-distroless-static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER nonroot:nonroot

ENTRYPOINT ["/manager"]
