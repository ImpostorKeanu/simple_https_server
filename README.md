# Purpose

This python3.6 script simplifies the process of bringing a TLS encrypted HTTPS
server online. It can generate a random self-signed certificate or accept values
pointing to one on disk.

*Now supports webroot configuration and basic auth!*

# Thanks

Special thanks to @touilleMan and @UniIsland for providing code to support
file uploads. 

# Dependencies

Python3.6 is required minimally. If being implemented on a Debian Stretch instance,
then the sources file needs to be updated to pull from the testing repositories.:

```
deb http://deb.debian.org/debian testing main contrib non-free
deb-src http://deb.debian.org/debian testing main contrib non-free
```

If being deployed on a Digital Ocean VPS, the following lines will need to be updated
in the sources list:

```
deb http://mirrors.digitalocean.com/debian testing main contrib non-free
deb-src http://mirrors.digitalocean.com/debian testing main contrib non-free
```

Finally, install all the junk: `install.sh`

# Examples

## Getting Help

```
user@computer:simple_https_server~> python3.6 server.py -h
Usage: SimpleHTTPSServer [-h] --interface INTERFACE [--port PORT]
                         [--webroot WEBROOT] [--certfile CERTFILE]
                         [--keyfile KEYFILE] [--generate]
                         [--gcertfile GCERTFILE] [--gkeyfile GKEYFILE]
                         [--basic-username BASIC_USERNAME]
                         [--basic-password BASIC_PASSWORD]

Start a listening HTTPS server.

optional arguments:
  -h, --help            show this help message and exit

Basic Server Configuration:
  Use the following parameters to apply basic server configurations

  --interface INTERFACE, -i INTERFACE
                        Interface/IP address the server will bind to.
  --port PORT, -p PORT  Port the server will listen on.
  --webroot WEBROOT, -wr WEBROOT
                        Directory from which to serve files.

x509 Certificate Configuration:
  Use the following parameters to configure the HTTPS certificate

  --certfile CERTFILE, -c CERTFILE
                        Certificate file for the server to use
  --keyfile KEYFILE, -k KEYFILE
                        Keyfile corresponding to certificate file
  --generate, -g        Generate and use a self-signed certificate in /tmp.
  --gcertfile GCERTFILE
                        Path to certificate file to be generated.
  --gkeyfile GKEYFILE   Path to keyfile to be generated.

Basic Authentication:
  Use the following parameters to configure the server to use basic
  authentication.

  --basic-username BASIC_USERNAME, -bu BASIC_USERNAME
                        Username for basic authentication
  --basic-password BASIC_PASSWORD, -pu BASIC_PASSWORD
                        Password for basic authentication

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

# Docker

This can also be implemented as a Docker container by making use of the provided
Dockerfile.

## Building from the image

Build a docker image by changing to the main git directory and running:

```
docker build -t shttpss:latest .
```

## Running the container

### Environment Variables

The following environment variables can be passed while running the server:

|Variable|Usage|Default|
|---|---|---|
|USERNAME|Username for basic authentication|No default|
|PASSWORD|Password for basic authentication|No default|
|ENABLE\_UPLOADS|Integer value determining if uploads should be allowed|1|
|ENABLE\_B64|Integer value that toggles support for base64 encoded file transfers|1|
|DISABLE\_CACHING|Integer value that toggles support for caching|1|

Each variable can be set using one or more `-e` flags as shown in the following
example.

### Configuring the Webroot

If you'd like to have the webroot accessible from the host and not just the
container instance, use a volume. The example makes use of this technique to
share from a directory from the `/tmp` folder.

**NOTE:** The container path to the webroot must be: `/root/webroot`

### User-Provided x509 Certificates

User-supplied x509 certificates can be passed to the server by making use
of volumes, as specified by the `-v` flag. The following table summarizes
where the volumes should be mounted within the container, as demonstrated
in the example.

|File|Container Path|
|---|---|
|Certificate File|/root/certificate|
|Private Key File|/root/key|

### Example

The following commands would create a new webroot directory on the supporting
host at `/tmp/webroot` and then initialize a container configured with a specific
keypair for for encryption. Once running, the the containerized web server would
be accessible on port `8443` of the supporting host that would be proxied to port
`443` of the containerized environment.

```bash
# Make a temporary webroot
mkdir /tmp/webroot

# Run the container
docker run \
  -e USERNAME=bhis -e PASSWORD=SuperSecretPassword123 \
  -v /tmp/webroot:/root/webroot \
  -v /tmp/cert:/root/certificate \
  -v /tmp/key:/root/key \
  -p 8443:443 \
  --rm \
  shttpss:latest
```
