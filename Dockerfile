# pingtxt-push-relay: one static Go binary on an empty image (~10 MB).

# Keep in sync with the "go" line of go.mod (CI checks it).
ARG GO_VERSION=1.26.10

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=$VERSION" -o /out/pingtxt-push-relay ./cmd/pingtxt-push-relay

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/pingtxt-push-relay /pingtxt-push-relay
# No shell, no package manager, no root: uid/gid 10001 like the pingtxt images.
USER 10001:10001
ENV RELAY_ADDR=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/pingtxt-push-relay", "healthcheck"]
ENTRYPOINT ["/pingtxt-push-relay"]
