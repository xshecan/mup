FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" -o /out/mup ./cmd/mup && \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" -o /out/mupctl ./cmd/mupctl

FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates iproute2 \
    iperf iperf3 unzip socat bash curl wget gzip nano mtr xz tar \
    inetutils-telnet netcat-openbsd iptables bind-tools nftables tcpdump
COPY --from=builder /out/mup /out/mupctl /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/mup"]
