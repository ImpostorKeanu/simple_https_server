#!/usr/bin/python3.6

import argparse
import http.server
import ssl
from OpenSSL import crypto, SSL

class ArgumentError(BaseException):
    pass

def suffix(st,suf='[+]'):
    return f'{suf} {st}'

def sprint(s):
    print(suffix(s))

def run_server(interface=None, port=None, keyfile=None, certfile=None):

    server_address = (interface, port)
    httpd = http.server.HTTPServer(server_address,
            http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
        server_side=True,
        certfile=certfile,
        keyfile=keyfile,
        ssl_version=ssl.PROTOCOL_TLSv1)

    try:
        sprint("Running https server")
        sprint("CTRL^C to exit")
        sprint("Log records below")
        print()
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        sprint("CTRL^C caught")
        sprint("Shutting down the server...")
        httpd.shutdown()
        sprint("Exiting")
        print()

def generate_certificate(certfile, keyfile):

    sprint("Generating self signed certificate")

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C  = "US"
    cert.get_subject().ST = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    cert.get_subject().L  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    cert.get_subject().O  = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    cert.get_subject().OU = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" 
    cert.get_subject().CN = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    sprint("Writing certificate and keyfile to disk")

    open(certfile, "wb").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(keyfile, "wb").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

if __name__ == '__main__':

    # certificate defaults
     # used for certificate generation
    certfile = '/tmp/self_signed.crt'
    keyfile = '/tmp/self_signed.key'

    parser = argparse.ArgumentParser(prog="SimpleHTTPSServer",
        description="Start a listening HTTPS server.")
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
    parser.add_argument('--gcertfile', default=certfile,
        help="Path to certificate file to be generated.")
    parser.add_argument('--gkeyfile', default=keyfile,
        help="Path to keyfile to be generated.")
    args = parser.parse_args()

    # error message
    m = None

    # assure certificate arguments are as expected
    if not args.certfile and not args.keyfile and not args.generate:
        m = """Script requires either --generate to be set or both of arguments
        for the --certfile and --keyfile parameters."""
    elif args.certfile and args.keyfile and args.generate:
        m = """Script requires either arguments for the certfile and keyfile
        parameters or, alternatively, the generate argument; not both"""
    
    if m:
        raise ArgumentError(m)

    print()
    print(parser.prog)
    print()
    sprint("Arguments validated successfully")

    if args.generate:
        generate_certificate(certfile, keyfile)
        args.certfile = certfile
        args.keyfile = keyfile

    # remove arguments prior to passing via **kwargs
    for attr in ['generate', 'gcertfile', 'gkeyfile']:
        args.__delattr__(attr)

    # **args.__dict__ because lazy
    run_server(**args.__dict__)
