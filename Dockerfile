FROM python:3.12-alpine

WORKDIR /app
RUN pip install --no-cache-dir dnslib
COPY mdns_announce.py .

ENTRYPOINT ["python3", "-u", "mdns_announce.py"]
