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
