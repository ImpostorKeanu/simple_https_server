# Purpose

This python3.6 script simplifies the process of bringing a TLS encrypted HTTPS
server online. It can generate a random self-signed certificate or accept values
pointing to one on disk.

# Dependencies

Python3.6 is required minimally. If being implemented on a Debian Stretch instance, then the sources file needs to be updated to pull from the testing repositories.:

```
deb http://deb.debian.org/debian testing main contrib non-free
deb-src http://deb.debian.org/debian testing main contrib non-free
```

If being deployed on a Digital Ocean VPS, the following lines will need to be updated in the sources list:

```
deb http://mirrors.digitalocean.com/debian testing main contrib non-free
deb-src http://mirrors.digitalocean.com/debian testing main contrib non-free
```

Finall, install all the junk: 

```
aptitude update
aptitude install python3-openssl python3-pip libffi-dev
python3.6 -m pip install -U pyOpenSSL
```

# Examples

## Getting Help

```
user@computer:simple_https_server~> python3.6 server.py -h
usage: SimpleHTTPSServer [-h] --interface INTERFACE --port PORT
                         [--certfile CERTFILE] [--keyfile KEYFILE]
                         [--generate] [--gcertfile GCERTFILE] [--gkey GKEY]

Start a listening HTTPS server.

optional arguments:
  -h, --help            show this help message and exit
  --interface INTERFACE, -i INTERFACE
                        Interface/IP address the server will bind to.
  --port PORT, -p PORT  Port the server will listen on.
  --certfile CERTFILE, -c CERTFILE
                        Certificate file for the server to uce
  --keyfile KEYFILE, -k KEYFILE
                        Keyfile corresponding to certificate file
  --generate, -g        Generate and use a self-signed certificate in /tmp.
  --gcertfile GCERTFILE
                        Path to certificate file to be generated.
  --gkeyfile GKEYFILE   Path to keyfile to be generated.
```

## Start the Server on localhost using a self-signed certificate

```
user@computer:simple_https_server~> python3 server.py -i 127.0.0.1 -p 8080 --generate

SimpleHTTPSServer

[+] Arguments validated successfully
[+] Generating self signed certificate
[+] Writing certificate and keyfile to disk
[+] Running https server
[+] CTRL^C to exit
[+] Log records below

127.0.0.1 - - [09/Jul/2018 15:08:05] "GET /server.py HTTP/1.1" 200 -
^C
[+] CTRL^C caught
[+] Shutting down the server...
[+] Exiting
```
