FROM debian:stable

# Update apt
RUN apt-get update

# Install non-python components
RUN apt-get install bash net-tools iproute2 -y

# Install python dependencies
RUN apt-get install python3.9 python3-pip python3-openssl -y

# Update SSL requirements for the os
RUN sed -r -e 's/MinProtocol =.+/MinProtocol = SSLv1/' -i /etc/ssl/openssl.cnf

# Create necessary paths
RUN mkdir /webroot

# Clone shttpss
#RUN git clone https://github.com/arch4ngel/simple_https_server /opt/git/shttpss
COPY ./ /root

# Install python packages
RUN pip3 install -r /root/requirements.txt

# =====================
# ENVIRONMENT VARIABLES
# =====================

###
# Basic authentication credentials
###
# NOTE: It's easier to set these at runtime via the "-e" flag
# e.g., -e USERNAME=bhis -e PASSWORD=SuperSecretPassword

# ENV USERNAME=username
# ENV PASSWORD=password

# Enable uploads by default
ENV ENABLE_UPLOADS=1

# Enable base64 encoding by default
ENV ENABLE_B64=1

# Disable caching at the server by default
ENV DISABLE_CACHING=1

### END ENVIRONMENT VARIABLES ###

EXPOSE 443/tcp

# Update apt
# Run runserver.sh
ENTRYPOINT ["/root/docker_runserver.sh"]
