FROM golang:1.26.1 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make

FROM ubuntu:noble-20251013 AS base

# Kamal's `proxy reboot` removes the old container with
#   docker container prune --filter label=org.opencontainers.image.title=kamal-proxy
# Upstream gets this label from its CI metadata step; a plain `docker build` of this fork
# did not carry it, so the stopped container kept its name and the new one failed to start
# (name conflict, exit 125) — leaving the host without a proxy. Bake the label into the image.
LABEL org.opencontainers.image.title="kamal-proxy" \
      org.opencontainers.image.source="https://github.com/fieldbots/kamal-proxy"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /app/bin/kamal-proxy /usr/local/bin/

EXPOSE 80 443

RUN useradd kamal-proxy \
    && mkdir -p /home/kamal-proxy/.config/kamal-proxy \
    && chown -R kamal-proxy:kamal-proxy /home/kamal-proxy

USER kamal-proxy:kamal-proxy

CMD ["kamal-proxy", "run"]
