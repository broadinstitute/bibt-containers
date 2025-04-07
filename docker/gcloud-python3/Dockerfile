ARG CLOUD_SDK_VERSION="517.0.0"

FROM google/cloud-sdk:${CLOUD_SDK_VERSION}

# install deps
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        libncurses5-dev=6.4-4 \
        libgdbm-dev=1.23-3 \
        libnss3-dev=2:3.87.1-1+deb12u1 \
        libssl-dev=3.0.15-1~deb12u1 \
        libsqlite3-dev=3.40.1-2+deb12u1 \
        libreadline-dev=8.2-1.3 \
        libffi-dev=3.4.4-1 \
        libbz2-dev=1.0.8-5+b1 \
        wget=1.21.3-1+deb12u1 \
        pkg-config=1.8.1-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# dl python
ARG PYTHON_VERSION="3.13.2"

WORKDIR /tmp
ENV PYTHON_VERSION=${PYTHON_VERSION}
RUN wget --progress=dot:giga "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
    && tar -xf Python-${PYTHON_VERSION}.tgz

# install python
WORKDIR /tmp/Python-${PYTHON_VERSION}
RUN ./configure --enable-optimizations \
    && make -j2 \
    && make install

ENV PYTHONUNBUFFERED=True
WORKDIR /

RUN python3 -m ensurepip \
    && python3 -m pip install --no-cache --no-cache-dir --upgrade \
        pip==25.0.1 \
        setuptools==78.1.0 \
        wheel==0.45.1

ENTRYPOINT [ "/bin/bash", "-l", "-c" ]
CMD ["echo 'gcloud-python3 container is running'"]
