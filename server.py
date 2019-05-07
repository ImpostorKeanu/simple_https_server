#!/usr/bin/env python3

import argparse
import http.server
import ssl
from pathlib import Path
from os import chdir
from OpenSSL import crypto, SSL
from random import randint
from base64 import b64encode, b64decode

class ArgumentError(BaseException):
    pass

def suffix(st,suf='[+]'):
    return f'{suf} {st}'

def sprint(s):
    print(suffix(s))

class BasicAuthServer(http.server.HTTPServer):

    def __init__(self, username, password, *args, **kwargs):
        self.key = str(b64encode(bytes(f'{username}:{password}','utf-8')),'utf-8')
        super().__init__(*args,**kwargs)

class BasicAuthHandler(http.server.SimpleHTTPRequestHandler):
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="simple_https_server", charset="UTF-8"')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if not self.headers.get('Authorization'):
            self.do_AUTHHEAD()
            self.wfile.write(bytes('No Authorization header received.','utf-8'))
        elif self.headers.get('Authorization') == f'Basic {self.server.key}':
            super().do_GET()
        else:
            self.do_AUTHHEAD()
            self.wfile.write(bytes(self.headers.get('Authorization'),'utf-8'))
            self.wfile.write(bytes('Not authenticated','utf-8'))

def run_server(interface, port, keyfile, certfile, 
        *args, **kwargs):
    
    server_address = (interface, port)

    # set up basic authentication if credentials are supplied
    if kwargs['basic_username']:

        assert kwargs['basic_username'] and kwargs['basic_password'],(
            ''''basic_username and basic_password are required
            for basic authentication'''
        )

        httpd = BasicAuthServer(kwargs['basic_username'],
                kwargs['basic_password'],
                server_address,
                BasicAuthHandler)

    # just do a regular https server if no credentials are supplied
    else:

        httpd = http.server.HTTPServer(server_address,
                http.server.SimpleHTTPRequestHandler)


    # wrap the httpd socket in ssl
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
    cert.get_subject().ST = str(randint(1,10000000))
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


    parser = argparse.ArgumentParser(prog="SimpleHTTPSServer",
        description="Start a listening HTTPS server.")

    server_group = parser.add_argument_group('Basic Server Configuration',
        '''Use the following parameters to apply basic server
        configurations''')
    server_group.add_argument('--interface', '-i', required=True,
        help="Interface/IP address the server will bind to.")
    server_group.add_argument('--port', '-p', default=443, type=int,
        help="Port the server will listen on.")
    server_group.add_argument('--webroot','-wr',
        default='.',
        help='Directory from which to serve files.')

    cert_group = parser.add_argument_group('x509 Certificate Configuration',
        '''Use the following parameters to configure the HTTPS certificate
        ''')
    cert_group.add_argument('--certfile', '-c', default=None,
        help="Certificate file for the server to use")
    cert_group.add_argument('--keyfile', '-k', default=None,
        help="Keyfile corresponding to certificate file")
    
    # certificate defaults
     # used for certificate generation
    certfile = '/tmp/self_signed.crt'
    keyfile = '/tmp/self_signed.key'
    cert_group.add_argument('--generate', '-g', default=None, action='store_true',
        help="Generate and use a self-signed certificate in /tmp.")
    cert_group.add_argument('--gcertfile', default=certfile,
        help="Path to certificate file to be generated.")
    cert_group.add_argument('--gkeyfile', default=keyfile,
        help="Path to keyfile to be generated.")

    auth_arg_group = parser.add_argument_group('Basic Authentication',
        '''Use the following parameters to configure the server to use
        basic authentication.
        ''')
    auth_arg_group.add_argument('--basic-username','-bu',
        help='Username for basic authentication')
    auth_arg_group.add_argument('--basic-password','-pu',
        help='Password for basic authentication')

    args = parser.parse_args()
    
    # handle basic auth credentials
    if args.basic_username and not args.basic_password or (
        args.basic_password and not args.basic_username):
        raise ArgumentError("""Script requires a username and password for
        basic authentication""")

    # assure certificate arguments are as expected
    if not args.certfile and not args.keyfile and not args.generate:
        raise ArgumentError(
        """Script requires either --generate to be set or both of arguments
        for the --certfile and --keyfile parameters.""")
    elif args.certfile and args.keyfile and args.generate:
        raise ArgumentError(
        """Script requires either arguments for the certfile and keyfile
        parameters or, alternatively, the generate argument; not both""")

    if args.webroot != '.':

        p = Path(args.webroot)

        if not p.exists():
            raise ArgumentError('''Path to webroot does not exist
            ''')
        elif not p.is_dir():
            raise ArgumentError('''Webroot is not a directory
            ''')

        chdir(args.webroot)

    print()
    print(parser.prog)
    print()
    sprint("Arguments validated successfully")


    if args.generate:
        generate_certificate(certfile, keyfile)
        args.certfile = certfile
        args.keyfile = keyfile

    run_server(**args.__dict__)
