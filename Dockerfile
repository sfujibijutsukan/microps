FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        sudo \
        build-essential \
        git \
        iproute2 \
        iputils-ping \
        netcat-openbsd \
        gcc-multilib \
        qemu-system-x86 && \
    update-ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace