#!/bin/bash

wrap () {
    echo -e "\e[93m$1\e[0m" 
}

if [ $UID != 0 ]; then
    wrap 'Installer must run as root'
    exit
fi

wrap 'Installing APT Packages'
apt-get update
apt-get install python3 python3-pip python3-openssl python3-pip libffi-dev
wrap 'Installing Python Packages'
python3 -m pip install -r requirements.txt
