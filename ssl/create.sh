# generate private key
# openssl genrsa -out csr.key 2048

# CA
openssl req -new -x509 -keyout cert/ca.key -out cert/ca.pem -days 3600 -config ./ca.cnf

# server
openssl req -new  -out cert/server.csr -keyout cert/server.key -config ./server.cnf

# sign it
# -key $(PASSWORD_CA) (default pwd is whatever2020)
openssl ca -batch -keyfile cert/ca.key -cert cert/ca.pem -in cert/server.csr -key whatever2020 -out cert/server.crt -extensions xpserver_ext -extfile xpextensions -config ./server.cnf

# sign it
# openssl x509 -req -in csr.pem -signkey private-key.pem -out public-cert.pem
