# Test image: Rust toolchain plus what the prebuilt libwebrtc of the LiveKit SDK needs to link.
FROM rust:1.88-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends lsb-release wget gnupg software-properties-common \
    libglib2.0-dev libclang-dev pkg-config libjpeg62-turbo-dev libx11-dev libxext-dev \
    libxfixes-dev libxdamage-dev libxrandr-dev libxcomposite-dev libgl1-mesa-dev libva-dev libdrm-dev \
 && wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh && bash /tmp/llvm.sh 21 \
 && rm -rf /var/lib/apt/lists/* /tmp/llvm.sh
ENV CC=clang-21 CXX=clang++-21
RUN rustup component add clippy rustfmt
