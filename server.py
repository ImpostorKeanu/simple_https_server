#!/usr/bin/python3.6

import http.server
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
import ssl
import argparse

class ArgumentError(BaseException):
    pass

def suffix(st,suf='[+]'):
    return f'{suf} {st}'

def sprint(s):
    print(suffix(s))

def run_server(interface=None, port=None, keyfile=None, certfile=None):

    sprint("Running https server")
    sprint("CTRL^C to exit")
    sprint("Log records below")
    print()
    server_address = (interface, port)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
        server_side=True,
        certfile=certfile,
        keyfile=keyfile,
        ssl_version=ssl.PROTOCOL_TLSv1)
    httpd.serve_forever()

def generate_certificate(certfile, keyfile):

    sprint("Generating self signed certificate")

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    cert.get_subject().L = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    cert.get_subject().O = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    cert.get_subject().OU = "Some Organization"
    cert.get_subject().CN = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    open(certfile, "wb").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(keyfile, "wb").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    sprint("Done")

if __name__ == '__main__':

    certfile = '/tmp/self_signed.crt'
    keyfile = '/tmp/self_signed.key'

    parser = argparse.ArgumentParser(description="Start a listening HTTPS server.")
    parser.add_argument('--interface', '-i', required=True,
        help="Interface/IP address the server will bind to.")
    parser.add_argument('--port', '-p', required=True, type=int,
        help="Port the server will listen on.")
    parser.add_argument('--certfile', '-c', default=None,
        help="Certificate file for the server to uce")
    parser.add_argument('--keyfile', '-k', default=None,
        help="Keyfile corresponding to certificate file")
    parser.add_argument('--generate', '-g', default=None, action='store_true',
        help="Generate and use a self-signed certificate in /tmp.")
    args = parser.parse_args()

    if not args.certfile and not args.keyfile and not args.generate:
        m = """Script requires either --generate to be set or both of arguments
        for the --certfile and --keyfile parameters."""
    elif args.certfile and args.keyfile and args.generate:
        m = """Script requires either arguments for the certfile and keyfile
        parameters or, alternatively, the generate argument; not both"""
    else:
        m = None

    if m:
        raise ArgumentError(m)

    if args.generate:
        generate_certificate(certfile, keyfile)
        args.certfile = certfile
        args.keyfile = keyfile

    args.__delattr__('generate')
    run_server(**args.__dict__)
