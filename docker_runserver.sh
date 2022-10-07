#!/bin/bash

export ADDR=$(ip a show eth0 | grep "inet " | awk '{print $2}' | sed -r -e 's/\/.+//')
export CMD="/usr/bin/python3 /root/server.py -i $ADDR -p 443 -wr /root/webroot"

# =================================================
# DETERMINE IF CERTIFICATE FILES HAVE BEEN PROVIDED
# =================================================

if [[ -f /root/certificate && ! -d /root/certificate ]]; then
    cert=1
else
    cert=0
fi

if [[ -f /root/key && ! -d /root/key ]]; then
    key=1
else
    key=0
fi

if [[ $cert = 1 && $key = 0 ]]; then
    echo "Certificate supplied without key";
    exit;
elif [[ $key = 1 && $cert = 0 ]]; then
    echo "Key supplied without certificate";
    exit;
elif [[ $key = 1 && $cert = 1 ]]; then
    echo "User supplied certificate and key will be used";
    CMD="$CMD -c /root/certificate -k /root/key"
else
    echo "Generating x509 keypair"
    CMD="$CMD -g"
fi

# ===========================================
# DETERMINE IF CREDENTIALS HAVE BEEN PROVIDED
# ===========================================

if [[ $USERNAME && $PASSWORD ]]; then
    echo "Using user-supplied credentials for basic authentication";
    CMD="$CMD -bu $USERNAME -bp $PASSWORD"
elif [[ $USERNAME && ! $PASSWORD ]]; then
    echo "Username supplied with no password. Exiting.";
    exit;
elif [[ ! $USERNAME && $PASSWORD ]]; then
    echo "Password supplied with no username. Exiting.";
    exit;
else
    echo "Credentials not supplied.";
    echo "⚠️ WARNING: Basic authentication disabled!"
fi

# =====================
# CONSTRUCT THE COMMAND
# =====================

if [[ $ENABLE_B64 = 1 ]]; then
    echo "Base64 encoding of files enabled.";
    CMD="$CMD --enable-b64"
fi

if [[ $ENABLE_UPLOADS = 1 ]]; then
    echo "File uploads enabled.";
    CMD="$CMD -eu"
fi

if [[ $DISABLE_CACHING = 1 ]]; then
    echo "Server-side caching disabled.";
    CMD="$CMD -dc"
fi

echo -e "\n-- Starting server on $ADDR (Webroot: /root/webroot, Credentials: $USERNAME:$PASSWORD) -- \n"
/bin/bash -c "$CMD"
