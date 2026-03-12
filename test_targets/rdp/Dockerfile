# RDP Test Target - NLA Mock Server
# Validates credentials at the NTLM layer for proper +auth-only testing
# Credentials: admin:admin, root:root

FROM python:3.11-alpine

# Install openssl for certificate generation
RUN apk add --no-cache openssl

# Create certs directory
RUN mkdir -p /certs

# Generate self-signed certificate
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/key.pem -out /certs/cert.pem \
    -days 365 -subj "/CN=rdp-test"

# Copy the NLA mock server
COPY rdp_nla_mock.py /app/rdp_nla_mock.py
RUN chmod +x /app/rdp_nla_mock.py

EXPOSE 3389

CMD ["python3", "/app/rdp_nla_mock.py"]
