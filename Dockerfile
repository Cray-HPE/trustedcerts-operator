# Build the manager binary
FROM arti.dev.cray.com/baseos-docker-master-local/golang:1.14.9-alpine3.12 AS builder

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

# TODO: Integrate test env from makefile
RUN make test

# Lint 
RUN ./util/golint -set_exit_status ./cmd/... ./internal/...

# Build
RUN go build -mod="vendor" -a -o manager ./cmd/manager/main.go

FROM arti.dev.cray.com/baseos-docker-master-local/alpine:3.12.7
WORKDIR /
COPY --from=builder /workspace/manager .
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot
USER nonroot:nonroot

ENTRYPOINT ["/manager"]
