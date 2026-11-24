# syntax=docker/dockerfile:1
# Multi-arch image: docker buildx build --platform linux/arm/v6,linux/arm/v7,linux/arm64,linux/amd64 .
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
RUN apk add --no-cache ca-certificates && mkdir /out /out/data
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/honet ./cmd/honet

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/honet /honet
COPY --from=build /out/data /data
ENV HONET_DATA_DIR=/data
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/honet"]
CMD ["serve"]
