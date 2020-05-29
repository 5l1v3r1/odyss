#!/bin/bash

CLIENT="$1"

cd /etc/openvpn/easy-rsa/
./easyrsa --batch revoke $CLIENT
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
rm -f pki/reqs/$CLIENT.req
rm -f pki/private/$CLIENT.key
rm -f pki/issued/$CLIENT.crt
rm -f /etc/openvpn/crl.pem
rm -f /home/op/profiles/$CLIENT.ovpn
cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
chown nobody:nogroup /etc/openvpn/crl.pem