openssl genrsa -out private-key.pem 1024
openssl req -new -key private-key.pem -out csr.pem
