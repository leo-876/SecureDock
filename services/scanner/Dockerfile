FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl nodejs npm && \
    npm install -g snyk && \
    apt-get clean

WORKDIR /app
COPY scan.py .

CMD ["python", "scan.py"]
