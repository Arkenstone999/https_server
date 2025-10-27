set -e
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"
chmod 600 certs/key.pem
chmod 644 certs/cert.pem