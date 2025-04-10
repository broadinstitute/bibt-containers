# Use a slim Python image
FROM python:3.12-slim

ARG NMAP_VERSION="7.93+dfsg1-1"
ARG CURL_VERSION="7.88.1-10+deb12u12"
ARG CA_CERTIFICATES_VERSION="20230311"
RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        nmap=$NMAP_VERSION \
        curl=$CURL_VERSION \
        ca-certificates=$CA_CERTIFICATES_VERSION \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY src/requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Copy script
COPY src/*.py .

ENV PYTHONUNBUFFERED=1

# Set default command
ENTRYPOINT ["python3", "/app/main.py"]
