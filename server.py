#!/usr/bin/env python3

import argparse
import http.server
import ssl
from pathlib import Path
from os import chdir, remove
import os
import posixpath
from random import randint
from base64 import b64encode, b64decode
from http import HTTPStatus
from urllib import parse
import datetime
import html
import shutil
import mimetypes
import re
from io import BytesIO, StringIO
import email
from hashlib import md5
from OpenSSL import crypto

'''
Credit to the following people for providing file upload capabilities:
    - https://gist.github.com/touilleMan
        - https://gist.github.com/touilleMan/eb02ea40b93e52604938
    - https://gist.github.com/UniIsland
        - https://gist.github.com/UniIsland/3346170
'''

def md5sum(data):
    m = md5()
    m.update(data)
    return m.hexdigest()

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

def do_POST(self):
    """Serve a POST request."""
    r, info = self.deal_post_data()
    f = BytesIO()
    f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
    f.write(b"<html>\n<title>Upload Result Page</title>\n")
    f.write(b"<body>\n<h2>Upload Result Page</h2>\n")
    f.write(b"<hr>\n")
    if r:
        f.write(b"<strong>Success: </strong>")
    else:
        f.write(b"<strong>Failed: </strong>")
    f.write(info.encode())
    f.write(("<br><a href=\"%s\">back</a>" % self.headers['referer']).encode())
    f.write(b"</small></body>\n</html>\n")
    length = f.tell()
    f.seek(0)
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(length))
    self.end_headers()
    if f:
        self.copyfile(f, self.wfile)
        f.close()

def upload_form(self):

    f = StringIO()
    if self.B64_ENCODE_PAYLOAD:
        f.write("<form ENCTYPE=\"multipart/form-data\" method=\"post\" onsubmit=\"return encoder(2);\">")
    else:
        f.write("<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
    f.write("<input name=\"file\" type=\"file\"/><br><br>")
    f.write("<input name=\"submit\" type=\"submit\" value=\"Upload\"/>")
    f.write("<input name=\"refresh\" type=\"button\"  onclick=\"loadFiles();\" value=\"Refresh Files\"/>")
    if self.B64_ENCODE_PAYLOAD:
        f.write("<br><br><input name=\"encodeCheckbox\" type=\"checkbox\" checked onchange=\"toggleEncodeUploads();\">")
        f.write("<label for=\"encodeCheckbox\">Base64 encode before <b>uploading</b></label>")

    f.write("</form>\n")
    f.seek(0)
    return f.read().encode()

def list_files(self, path, b64_encoded):

    try:
        file_list = os.listdir(path)
        file_list.insert(0, "..")
    except os.error:
        self.send_error(404, "No permission to list directory")
        return None

    file_list.sort(key=str.casefold)

    # io object to receive links
    f = StringIO()

    # html escape the displaypath
    displaypath = html.escape(parse.unquote(self.path))

    # Generate download links
    for name in file_list:

        is_dir = False
        fullname = os.path.join(path, name)
        displayname = linkname = name

        # Append / for directories or @ for symbolic links
        if os.path.isdir(fullname):
            is_dir = True
            displayname = name + "/"
            linkname = name + "/"

        if os.path.islink(fullname):
            displayname = name + "@"
            # Note: a link to a directory displays with @ and links with /

        linkname = parse.quote(linkname)
        displayname = html.escape(displayname)

        # Handle insertion of JS links
        if self.B64_ENCODE_PAYLOAD and not is_dir:

            # implenet call to JS via onClick
            f.write(
                    self.B64_LINK.format(
                        linkname,
                        linkname,
                        displayname)
            )

        else:

            # Non-JS links
            f.write(
                '<li><a href="{}">{}</a>\n'.format(
                    linkname,
                    displayname
                )
            )

    # return the links as a binary string
    f.seek(0)
    return f.read().encode()

def list_directory(self, path, b64_encoded):
    """Helper to produce a directory listing (absent index.html).
    Return value is either a file object, or None (indicating an
    error).  In either case, the headers are sent, making the
    interface the same as for send_head().
    """
    try:
        file_list = os.listdir(path)
    except os.error:
        self.send_error(404, "No permission to list directory")
        return None
    file_list.sort(key=str.casefold)
    f = BytesIO()
    displaypath = html.escape(parse.unquote(self.path))
    f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
    f.write(("<html>\n<title>Directory listing for %s</title>\n" % displaypath).encode())
    f.write(("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath).encode())

    # Get the JavaScript template
    with open(str(Path(__file__).resolve().parent.absolute()) + \
            '/templates/b64_obfuscation.js','r') as infile:
        js_template = infile.read()

    # Embed JavaScript
    f.write("<script type='text/javascript'>\n{}</script>\n".format(
        js_template).encode('utf8')
    )

    # Generate the upload form
    f.write(b"<hr>\n"+
        self.upload_form()+
        b"<hr>\n<ul>\n")

    # Generate download links
    f.write(b"<div id=\"listing\"></div>")
    f.write(b"</ul>\n<hr>\n")

    # Checkbox to toggle decoding of downloaded files
    if self.B64_ENCODE_PAYLOAD:
        f.write(b"<input name=\"toggleEncodeDownloadCheckbox\" type=\"checkbox\" onchange=\"toggleEncodeDownloads();\" checked>")
        f.write(b"<label for=\"toggleEncodeDownloadCheckbox\">Base64 encode <b>before</b> downloading</label>")
        f.write(b"<br>")
        f.write(b"<input name=\"toggleDecodeCheckbox\" type=\"checkbox\" onchange=\"toggleDecodeDownloads();\" checked>")
        f.write(b"<label for=\"toggleDecodeCheckbox\">Base64 decode <b>after</b> downloading</label>")
        f.write(b"<br>")
        f.write(b"<input name=\"toggleDisplayB64\" type=\"checkbox\" onchange=\"toggleDisplayB64();\">")
        f.write(b"<label for=\"toggleDisplayB64\">Display Base64 encoded file <b>instead of downloading</b></label>")

    f.write(b"</body>\n</html>\n")
    length = f.tell()
    f.seek(0)
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(length))
    self.end_headers()
    return f

class CorsHandler(http.server.SimpleHTTPRequestHandler):

    B64_ENCODE_PAYLOAD = False
    B64_LINK = None
    BROWSER_DECODE_DISABLED = False
    B64_LINK_TEMPLATE = \
        '<li><a href="javascript:downloader(\'{}\')">{}</a></li>\n'

    @property
    def client_ip(self):
        return self.client_address[0]

    @property
    def client_port(self):
        return self.client_address[1]

    # Stolen directly from http.server.SimpleHTTPRequestHanlder because I couldn't
    # find a simple way to add an Access-Control-Allow-Origin headers since this
    # overridden method assembles the preliminary response and headers
    def send_head(self):
        """Common code for GET and HEAD commands.
        This sends the response code and MIME headers.
        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.
        """

        path, b64_encoded = self.translate_path(self.path)

        # Return to requests for files
        file_listing = False
        if path.endswith('/SHTTPSSgetFiles'):
            path = path.split('/SHTTPSSgetFiles')[0]
            file_listing = True

            f = BytesIO()
            f.write(self.list_files(path, b64_encoded))
            length = f.tell()
            f.seek(0)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(length))
            self.end_headers()
            return f

        f = None
        if os.path.isdir(path):
            parts = parse.urlsplit(self.path)

            # ====================================
            # REDIRECT BROWSER BACK TO PATH WITH /
            # ====================================
            'Only when in a directory, though'

            if not parts.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/',
                             parts[3], parts[4])
                new_url = parse.urlunsplit(new_parts)
                self.send_header("Location", new_url)
                self.end_headers()
                return None

            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                if CorsHandler.uploads_enabled:
                    return self.list_directory(path,b64_encoded)
                else:
                    return self.list_directory(path)


        ctype = self.guess_type(path)
        # check for trailing "/" which should return 404. See Issue17324
        # The test for this was added in test_httpserver.py
        # However, some OS platforms accept a trailingSlash as a filename
        # See discussion on python-dev and Issue34711 regarding
        # parseing and rejection of filenames with a trailing slash
        if path.endswith("/"):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        try:
            fs = os.fstat(f.fileno())
            if not CorsHandler.DISABLE_CACHING:
                # Use browser cache if possible
                if ("If-Modified-Since" in self.headers
                        and "If-None-Match" not in self.headers):
                    # compare If-Modified-Since and time of last file modification
                    try:
                        ims = email.utils.parsedate_to_datetime(
                            self.headers["If-Modified-Since"])
                    except (TypeError, IndexError, OverflowError, ValueError):
                        # ignore ill-formed values
                        pass
                    else:
                        if ims.tzinfo is None:
                            # obsolete format with no timezone, cf.
                            # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                            ims = ims.replace(tzinfo=datetime.timezone.utc)
                        if ims.tzinfo is datetime.timezone.utc:
                            # compare to UTC datetime of last modification
                            last_modif = datetime.datetime.fromtimestamp(
                                fs.st_mtime, datetime.timezone.utc)
                            # remove microseconds, like in If-Modified-Since
                            last_modif = last_modif.replace(microsecond=0)
    
                            if last_modif <= ims:
                                self.send_response(HTTPStatus.NOT_MODIFIED)
                                self.end_headers()
                                f.close()
                                return None

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", ctype)
            self.send_header("Last-Modified",
                self.date_time_string(fs.st_mtime))

            # Adding Access-Control-Allow-Origin header
            self.send_header('Access-Control-Allow-Origin','*')
            self.end_headers()

            if CorsHandler.B64_ENCODE_PAYLOAD and b64_encoded:

                # Read in the file and prepare for encoding
                encoded = f.read()
                self.log_message(
                    'Encoding target download file {} ({} bytes, md5sum: {})' \
                        .format(path,
                            len(encoded),
                            md5sum(encoded))
                )

                # TODO: Make iterations configurable
                for i in range(0,2): encoded = b64encode(encoded)

                encoded_length = len(encoded)

                self.log_message(
                    'File encoding success {} ({} bytes, md5sum: {})' \
                        .format(path,
                            encoded_length,
                            md5sum(encoded))
                )

                # Update the content-length header to reflect the length
                # of the encoded value
                self.send_header("Content-Length", encoded_length)
                return BytesIO(encoded)

            else:

                # Update the content-length header with the length of the
                # normal value
                self.send_header("Content-Length", str(fs[6]))

            return f

        except:
            f.close()
            raise

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.
        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)
        """

        # Capture B64 encoding parameter
        b64_encoded = False
        path = path.split('?',1)

        if len(path) > 1:
            path,query = path
            if query.find('true') > -1:
                b64_encoded = True
        else: path = path[0]

        path = path.split('#',1)[0]
        path = posixpath.normpath(parse.unquote(path))
        words = path.split('/')
        words = [_f for _f in words if _f]
        path = os.getcwd()
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)

        return path,b64_encoded
 
    def copyfile(self, source, outputfile):
        """Copy all data between two file objects.
        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).
        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.
        """
        shutil.copyfileobj(source, outputfile)
 
    def guess_type(self, path):
        """Guess the type of a file.
        Argument is a PATH (a filename).
        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.
        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.
        """
 
        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']
 
    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream', # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
        '.txt': 'text/plain',
        })

    def deal_post_data(self):

        content_type = self.headers['content-type']
        if not content_type:
            self.log_error("Content-Type header doesn't contain boundary")
            return (False, "Content-Type header doesn't contain boundary")
        boundary = content_type.split("=")[1].encode()
        remainbytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remainbytes -= len(line)
        if not boundary in line:
            self.log_error("Content does not begin with boundary")
            return (False, "Content NOT begin with boundary")
        line = self.rfile.readline()
        remainbytes -= len(line)
        fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', line.decode())
        if not fn:
            self.log_error("Can't find out file name...")
            return (False, "Can't find out file name...")

        path, b64_encoded = self.translate_path(self.path)
        fn = os.path.join(path, fn[0])

        # ==========================
        # BEGIN READING INPUT STREAM
        # ==========================

        line = self.rfile.readline()
        remainbytes -= len(line)
        line = self.rfile.readline()
        remainbytes -= len(line)

        self.log_message('Handling POST request: {} {}:{}'.format(
                fn, self.client_ip, self.client_port
            )
        )

        try:
            out = open(fn, 'wb')
        except IOError:
            self.log_error("Cannot write to target directory. (Permissions Problem)")
            return (False, "Can't create file to write, do you have permission to write?")
        
        # Read file content
        preline = self.rfile.readline()
        remainbytes -= len(preline)
        while remainbytes > 0:
            line = self.rfile.readline()
            remainbytes -= len(line)
            if boundary in line:
                preline = preline[0:-1]
                if preline.endswith(b'\r'):
                    preline = preline[0:-1]

                out.write(preline)
                out.close()

                # TODO: Handle decoding of uploads
                if CorsHandler.B64_ENCODE_PAYLOAD and b64_encoded:

                    # Read in the file content
                    with open(fn,'rb') as f: data = f.read()

                    self.log_message('Decoding uploaded file {} ({} bytes)' \
                        .format(fn, len(data)))

                    # Decode the data
                    for i in range(0,2): data = b64decode(data)

                    self.log_message('Decoded uploaded file {} ({} bytes, md5sum: {})' \
                        .format(fn, len(data), md5sum(data)))

                    # Open and write the decoded content
                    with open(fn,'wb') as f: f.write(data)

                self.log_message("File '%s' uploaded by '%s:%d'",fn, self.client_ip, self.client_port)
                return (True, "File '%s' upload success!" % fn)
            else:
                out.write(preline)
                preline = line

        self.log_message("Unexpected end of data")
        return (False, "Unexpected end of data")

class BasicAuthHandler(CorsHandler):
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="internal", charset="UTF-8"')
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

def do_basic_POST(self):

    if not self.headers.get('Authorization'):
        self.do_AUTHHEAD()
        self.wfile.write(bytes('No Authorization header received.','utf-8'))
    elif self.headers.get('Authorization') == f'Basic {self.server.key}':
        super(self.__class__,self).do_POST()
    else:
        self.do_AUTHHEAD()
        self.wfile.write(bytes(self.headers.get('Authorization'),'utf-8'))
        self.wfile.write(bytes('Not authenticated','utf-8'))

def run_server(interface, port, keyfile, certfile, 
        webroot=None, enable_uploads=False, enable_b64=False,
        disable_caching=False,
        *args, **kwargs):

    # ============================
    # CONFIGURE BASE64 OBFUSCATION
    # ============================

    CorsHandler.B64_ENCODE_PAYLOAD = enable_b64
    CorsHandler.DISABLE_CACHING = disable_caching

    if enable_b64:

        CorsHandler.B64_LINK = CorsHandler.B64_LINK_TEMPLATE

    webroot=webroot or '.'

    CorsHandler.list_files = list_files

    # Update CorsHandler with upload functionality
    if enable_uploads:

        BasicAuthHandler.do_POST = do_basic_POST    # Enforce authentication for upload
        CorsHandler.do_POST = do_POST               # POST method support
        CorsHandler.list_directory = list_directory # Modified directory listing
        CorsHandler.upload_form = upload_form
        CorsHandler.uploads_enabled = True

    else:

        CorsHandler.uploads_enabled = False
    
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
                CorsHandler)
    

    # wrap the httpd socket in ssl
    httpd.socket = ssl.wrap_socket(httpd.socket,
        server_side=True,
        certfile=certfile,
        keyfile=keyfile,
        ssl_version=ssl.PROTOCOL_TLSv1_2)

    chdir(webroot)

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
    finally:
        if kwargs['generate']:
            # only remove files if they weren't manually specified
            if certfile == "/tmp/self_signed.crt":
                remove('/tmp/self_signed.crt')
            if keyfile == "/tmp/self_signed.key":
                remove('/tmp/self_signed.key')

def generate_certificate(certfile, keyfile):

    sprint("Generating self signed certificate")

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4028)

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
    server_group.add_argument('--enable-uploads','-eu',
        action='store_true',
        help='Enable file uploads via POST request')
    server_group.add_argument('--disable-caching','-dc',
        action='store_true',
        help='Disable caching')

    cert_group = parser.add_argument_group('x509 Certificate Configuration',
        '''Use the following parameters to configure the HTTPS certificate
        ''')
    cert_group.add_argument('--certfile', '-c', default=None,
        help="Certificate file for the server to use")
    cert_group.add_argument('--keyfile', '-k', default=None,
        help="Keyfile corresponding to certificate file")
    
    # certificate defaults
    # used for certificate generation

    cert_gen_group = parser.add_argument_group('x509 Certificate Generation Configuration',
            '''Use the following parameters to override default certificate generation
            path and name
            ''')

    certfile = '/tmp/self_signed.crt'
    keyfile = '/tmp/self_signed.key'

    cert_gen_group.add_argument('--generate', '-g', default=None, action='store_true',
        help="Generate and use a self-signed certificate in /tmp.")
    cert_gen_group.add_argument('--gcertfile', '-gc', default=certfile,
        help="Path to certificate file to be generated.")
    cert_gen_group.add_argument('--gkeyfile', '-gk', default=keyfile,
        help="Path to keyfile to be generated.")

    auth_arg_group = parser.add_argument_group('Basic Authentication',
        '''Use the following parameters to configure the server to use
        basic authentication.
        ''')
    auth_arg_group.add_argument('--basic-username','-bu',
        help='Username for basic authentication')
    auth_arg_group.add_argument('--basic-password','-bp',
        help='Password for basic authentication')

    # obfuscation
    obf_group = parser.add_argument_group('Obfuscation',
        '''Configure the server to implement file obfuscation.
         JavaScript is injected into the browser to handle
         obfuscation at the client.
        ''')
    obf_group.add_argument('--enable-b64',
        help='Enable double base 64 obfuscation of files.',
        action='store_true')

    args = parser.parse_args()

    # handle basic auth credentials
    if args.basic_username and not args.basic_password or (
        args.basic_password and not args.basic_username):
        raise ArgumentError("""Script requires a username and password for
        basic authentication""")

    # ensure certificate arguments are as expected
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

    print()
    print(parser.prog)
    print()
    sprint("Arguments validated successfully")


    if args.generate:
        if args.certfile or args.keyfile:
            print("[!] Warning: cert and key file arguments are ignored when generating.")

        args.certfile = args.gcertfile
        args.keyfile = args.gkeyfile
        generate_certificate(args.certfile, args.keyfile)

    run_server(**args.__dict__)
