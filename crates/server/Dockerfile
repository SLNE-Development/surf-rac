# Build context: the repository root.
#   docker build -f crates/server/Dockerfile -t surf-rac-server .

FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p surf-rac-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home surfrac
COPY --from=build /src/target/release/surf-rac-server /usr/local/bin/surf-rac-server
USER surfrac
EXPOSE 8080
ENTRYPOINT ["surf-rac-server"]
CMD ["serve"]
