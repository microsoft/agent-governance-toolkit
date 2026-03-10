FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:9e7e09e8e63d9cc9646306d8642ad801fb2d32e5d70081edbfb200c46e1e0b5e

COPY . $SRC/agent-governance-toolkit
WORKDIR $SRC/agent-governance-toolkit

COPY .clusterfuzzlite/build.sh $SRC/build.sh
