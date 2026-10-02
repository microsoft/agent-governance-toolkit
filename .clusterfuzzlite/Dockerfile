FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:9e7e09e8e63d9cc9646306d8642ad801fb2d32e5d70081edbfb200c46e1e0b5e

COPY . $SRC/agent-governance-toolkit
WORKDIR $SRC/agent-governance-toolkit

# Keep the image's Cargo coverage wrapper and provide its missing compiler.
# Nightly is required by OSS-Fuzz's -Zsanitizer flags.
RUN bash scripts/ci/install_pinned_rust.sh "" nightly-2025-08-07 \
    && mkdir -p /rust/bin \
    && ln -s /root/.cargo/bin/cargo /rust/bin/cargo
ENV PATH="${PATH}:/root/.cargo/bin"

COPY .clusterfuzzlite/build.sh $SRC/build.sh
