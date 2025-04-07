FROM alpine:3.21.3 AS builder

ARG WGET_VERSION="1.25.0"
ARG LIBPCAP_VERSION="1.10.5"
ARG GIT_VERSION="2.47.2"
ARG MAKE_VERSION="4.4.1"
ARG GCC_VERSION="14.2.0"
ARG LIBC_DEV_VERSION="1.2.5"
ARG LINUX_HEADERS_VERSION="6.6"

RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache --update \
        wget=~${WGET_VERSION} \
        git=~${GIT_VERSION} \
        make=~${MAKE_VERSION} \
        gcc=~${GCC_VERSION} \
        g++=~${GCC_VERSION} \
        libc-dev=~${LIBC_DEV_VERSION} \
        linux-headers=~${LINUX_HEADERS_VERSION} \
        libpcap=~${LIBPCAP_VERSION}

ARG MASSCAN_COMMIT_HASH="a31feaf5c943fc517752e23423ea130a92f0d473" # pragma: allowlist secret

WORKDIR /build
RUN git clone https://github.com/robertdavidgraham/masscan

WORKDIR /build/masscan
RUN git checkout ${MASSCAN_COMMIT_HASH} \
    && git submodule update --init --recursive \
    && git submodule foreach git clean -fdx \
    && make -j"$(nproc)"

FROM alpine:3.21.3

LABEL maintainer="mobrien@broadinstitute.org" \
      org.opencontainers.image.title="masscan" \
      org.opencontainers.image.source="https://github.com/robertdavidgraham/masscan"

ARG LIBPCAP_VERSION="1.10.5"
RUN apk update && apk upgrade --no-cache \
    && apk add --no-cache \
        libpcap=~${LIBPCAP_VERSION}

COPY --from=builder /build/masscan/LICENSE /usr/share/doc/masscan/LICENSE
COPY --from=builder /build/masscan/bin/masscan /usr/bin/masscan

HEALTHCHECK CMD [ "masscan", "--version" ]

ENTRYPOINT ["/usr/bin/masscan"]
CMD ["--help"]
