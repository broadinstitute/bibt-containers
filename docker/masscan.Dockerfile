# syntax=docker/dockerfile:1

ARG GCLOUD_SDK_VERSION="517.0.0"

FROM google/cloud-sdk:${GCLOUD_SDK_VERSION}

ARG MASSCAN_COMMIT_HASH="a31feaf5c943fc517752e23423ea130a92f0d473" # pragma: allowlist secret
ARG WGET_VERSION="1.21.3-1+deb12u1"
ARG LIBPCAP_VERSION="1.10.3-1"

RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        wget=${WGET_VERSION} \
        libpcap0.8=${LIBPCAP_VERSION} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone https://github.com/robertdavidgraham/masscan
WORKDIR /tmp/masscan
RUN git checkout ${MASSCAN_COMMIT_HASH} \
    && git submodule update --init --recursive \
    && git submodule foreach git checkout ${MASSCAN_COMMIT_HASH} \
    && git submodule foreach git pull origin ${MASSCAN_COMMIT_HASH} \
    && git submodule foreach git clean -fdx \
    && make -j \
    && make install

WORKDIR /

ENTRYPOINT ["/usr/bin/masscan"]
CMD ["--help"]
