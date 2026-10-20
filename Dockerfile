FROM docker.io/library/golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /op-gate .

# Pinned by digest: op-gate's allowlist depends on op's subcommand names, so
# op upgrades arrive as reviewed Renovate PRs, never silently.
FROM docker.io/1password/op:2.41.0@sha256:c218de9c39ac1a65ca1e98b634aa132bee1ff94d762d01d5cdfeebbc3413c697
COPY --from=build /op-gate /usr/local/bin/op-gate
EXPOSE 18340 8080
ENTRYPOINT ["/usr/local/bin/op-gate"]
