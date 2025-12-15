# Dockerfile for caddy-saml-disco
# Uses pre-built binary from release artifacts
#
# Build args:
#   TARGETARCH - automatically set by Docker buildx (amd64, arm64)
#
# Usage:
#   docker build -t caddy-saml-disco .
#   docker run -p 80:80 -p 443:443 -v $PWD/Caddyfile:/etc/caddy/Caddyfile caddy-saml-disco

FROM alpine:3.21

# Install ca-certificates for HTTPS and tzdata for timezone support
RUN apk add --no-cache ca-certificates tzdata

# Create caddy user/group
RUN addgroup -S caddy && adduser -S -G caddy caddy

# Copy pre-built binary (set by build workflow)
ARG TARGETARCH
COPY caddy-saml-disco-linux-${TARGETARCH} /usr/bin/caddy

# Make executable
RUN chmod +x /usr/bin/caddy

# Create directories Caddy expects
RUN mkdir -p /config/caddy /data/caddy /etc/caddy \
    && chown -R caddy:caddy /config /data /etc/caddy

# Default Caddyfile location
VOLUME /etc/caddy
VOLUME /data
VOLUME /config

# Standard HTTP/HTTPS ports
EXPOSE 80 443 443/udp 2019

# Run as non-root
USER caddy

# Set working directory
WORKDIR /srv

# Default command
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
