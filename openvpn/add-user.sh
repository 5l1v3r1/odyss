#!/bin/bash

CLIENT="$1"
OVPN_CONFIG_PATH="/tmp"

cd /etc/openvpn/easy-rsa/
EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full $CLIENT nopass

cp /etc/openvpn/client-common.txt $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "<ca>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
cat /etc/openvpn/easy-rsa/pki/ca.crt >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "</ca>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "<cert>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "</cert>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "<key>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
cat /etc/openvpn/easy-rsa/pki/private/$CLIENT.key >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "</key>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "<tls-auth>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/ta.key >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
echo "</tls-auth>" >> $OVPN_CONFIG_PATH/$CLIENT.ovpn
cp $OVPN_CONFIG_PATH/$CLIENT.ovpn /home/op/profiles/$CLIENT.ovpn
chown op:users /home/op/profiles/$CLIENT.ovpn