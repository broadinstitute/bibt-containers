# Use a slim Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY src/requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Copy script
COPY src/main.py .

ENV PYTHONUNBUFFERED=1

# Set default command
ENTRYPOINT ["python3", "/app/main.py"]
