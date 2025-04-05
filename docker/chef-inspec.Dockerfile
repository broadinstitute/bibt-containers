ARG INSPEC_VERSION
ARG GCLOUD_PYTHON3_VERSION

FROM us-docker.pkg.dev/bibt-containers/docker/gcloud-python3:${GCLOUD_PYTHON3_VERSION}

RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y curl=8.13.0-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV INSPEC_VERSION=${INSPEC_VERSION}
RUN curl https://omnitruck.chef.io/install.sh | /bin/bash -s -- -P inspec -v "${INSPEC_VERSION}"
ENV CHEF_LICENSE accept
