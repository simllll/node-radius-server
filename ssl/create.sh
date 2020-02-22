# generate private key
# openssl genrsa -out csr.key 2048

# CA
openssl req -new -x509 -keyout ca.key -out ca.pem -days 3600 -config ./ca.cnf

# server
openssl req -new  -out server.csr -keyout server.key -config ./server.cnf

# sign it
# -key $(PASSWORD_CA) (default pwd is whatever2020)
openssl ca -batch -keyfile ca.key -cert ca.pem -in server.csr -key whatever2020 -out server.crt -extensions xpserver_ext -extfile xpextensions -config ./server.cnf

# sign it
# openssl x509 -req -in csr.pem -signkey private-key.pem -out public-cert.pem
