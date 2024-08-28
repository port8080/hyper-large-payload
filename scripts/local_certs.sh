#!/bin/bash

# 1. Generate CA's private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -days 1825 -nodes -keyout repro-ca-key.pem -out repro-ca-cert.pem -subj "/C=US/CN=repro root CA"

# 2. Generate web server's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -keyout server-key.pem -out server-req.pem -subj "/C=US/CN=localhost"

# 3. Use CA's private key to sign web server's CSR and get back the signed certificate
printf "subjectAltName=DNS:%s\n" "localhost" > server-ext.cnf
openssl x509 -req -in server-req.pem -days 60 -CA repro-ca-cert.pem -CAkey repro-ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf
