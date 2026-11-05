# Image du serveur MCP : binaire statique (musl) dans une image vide, sans shell ni système.
# Construction : docker build -t osmcp rust
# Usage       : docker run -i --rm -e OPNSENSE_URL=... -e OPNSENSE_API_KEY=... -e OPNSENSE_API_SECRET=... osmcp
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock endpoints.json ./
COPY src ./src
RUN cargo build --release --locked

FROM scratch
LABEL org.opencontainers.image.title="osmcp" \
      org.opencontainers.image.description="Serveur MCP pour pare-feu OPNsense (portage Rust)" \
      org.opencontainers.image.source="https://github.com/TojiiSamaa/opnmcp" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /src/target/release/osmcp /osmcp
USER 65532:65532
EXPOSE 8765
ENTRYPOINT ["/osmcp"]
