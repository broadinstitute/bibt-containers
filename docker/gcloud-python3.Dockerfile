ARG PYTHON_VERSION
ARG CLOUD_SDK_VERSION

FROM google/cloud-sdk:${CLOUD_SDK_VERSION}

# install deps
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y wget=1.25.0-2 build-essential=12.12 \
        zlib1g-dev=1:1.3.dfsg+really1.3.1-1 libncurses5-dev=6.5+20250216-2 libgdbm-dev=1.24-2 \
        libnss3-dev=2:3.110-1 libssl-dev=3.4.1-1 libsqlite3-dev=3.46.1-2 libreadline-dev=8.2-6 \
        libffi-dev=3.4.7-1 curl=8.13.0-1 libbz2-dev=1.0.8-6 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# dl python
WORKDIR /tmp
ENV PYTHON_VERSION=${PYTHON_VERSION}
RUN wget --progress=dot:giga "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
    && tar -xf Python-${PYTHON_VERSION}.tgz

# install python
WORKDIR /tmp/Python-${PYTHON_VERSION}
RUN ./configure --enable-optimizations \
    && make -j \
    && make install

ENV PYTHONUNBUFFERED True
WORKDIR /
