#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

gcc -o gen_chain gen_chain.c

rm -rf RootCA.key RootCA.crt  RootCA.der RootKey.der
rm -rf IntermediateCA.key IntermediateCA.csr  IntermediateCA.crt IntermediateCA.der
rm -rf Server.key Server.csr Server.crt  ServerCA.der ServerKey.der
rm -rf ServerCert.der

openssl req -newkey rsa:2048 -nodes -keyout RootCA.key -new -x509 -days 1000 -out RootCA.crt \
	-subj "/C=CA/ST=ON/L=Ottawa/O=ROOT/OU=A/CN=lucien.xin@gmail.com"
openssl req -newkey rsa:2048 -nodes -keyout IntermediateCA.key -out IntermediateCA.csr \
	-subj "/C=CA/ST=ON/L=Ottawa/O=Intermediate/OU=B/CN=lucien.xin@gmail.com"
openssl x509 -req -days 1000 -in IntermediateCA.csr -CA RootCA.crt -CAkey RootCA.key \
	-CAcreateserial -out IntermediateCA.crt -extfile openssl.cnf
openssl req -newkey rsa:2048 -nodes -keyout Server.key -out Server.csr \
	-subj "/C=CA/ST=ON/L=Ottawa/O=Server/OU=C/CN=lucien.xin@gmail.com"
openssl x509 -req -days 1000 -in Server.csr -CA IntermediateCA.crt \
	-CAkey IntermediateCA.key -CAcreateserial -out Server.crt -extfile openssl.cnf

openssl x509 -outform der -in RootCA.crt -out RootCA.der
openssl rsa -outform der -in RootCA.key -out RootKey.der
openssl x509 -outform der -in IntermediateCA.crt -out IntermediateCA.der
openssl x509 -outform der -in Server.crt -out ServerCA.der
openssl rsa -outform der -in Server.key -out ServerKey.der

./gen_chain ServerCert.der ServerCA.der IntermediateCA.der RootCA.der
