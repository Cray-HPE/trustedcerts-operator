# Build the manager binary
FROM artifactory.algol60.net/docker.io/golang:1.14.15-alpine3.13 AS builder

RUN apk add --upgrade apk-tools &&  \
  apk update && apk -U upgrade && \
  apk add make bash curl && \
  rm -rf /var/cache/apk/*

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

FROM artifactory.algol60.net/docker.io/alpine:3.15.0

RUN apk add --upgrade apk-tools &&  \
  apk update && apk -U upgrade && \
  rm -rf /var/cache/apk/*

WORKDIR /
COPY --from=builder /workspace/manager .
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot
USER nonroot:nonroot

ENTRYPOINT ["/manager"]
