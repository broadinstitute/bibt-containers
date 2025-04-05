ARG MASSCAN_VERSION
ARG GCLOUD_PYTHON3_VERSION

FROM us-docker.pkg.dev/bibt-containers/docker/gcloud-python3:${GCLOUD_PYTHON3_VERSION}

RUN apt-get update && apt-get upgrade \
    && apt-get install --no-install-recommends -y git=1:2.49.0-1 gcc=1.220 make=4.4.1-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
ENV MASSCAN_VERSION=${MASSCAN_VERSION}
RUN mkdir /src \
    && wget --progress=dot:giga "https://github.com/robertdavidgraham/masscan/archive/refs/tags/${MASSCAN_VERSION}.tar.gz" \
    && tar -zxf /tmp/${MASSCAN_VERSION}.tar.gz -C /src

WORKDIR /src/masscan-${MASSCAN_VERSION}
RUN make -j \
    && make install
WORKDIR /
