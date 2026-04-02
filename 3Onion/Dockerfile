FROM debian:bullseye

RUN apt update && \
    apt install -y nginx \
                    openssh-server \
                    tor \
                    ca-certificates
                    
RUN ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_llave -N ""

RUN groupadd -g 1000 www && \
    useradd -m -d /home/www -u 1000 -g www -s /bin/bash www && \
    echo 'www:pruebas' | chpasswd && \
    mkdir -p /home/www/.ssh && \
    touch /home/www/.ssh/authorized_keys && \
    chown -R www:www /home/www/.ssh && \
    chmod 700 /home/www/.ssh && \
    chmod 600 /home/www/.ssh/authorized_keys

COPY index.html     /var/www/html/index.html
COPY nginx.conf     /etc/nginx/nginx.conf
COPY sshd_config    /etc/ssh/sshd_config
COPY torrc          /etc/tor/torrc
COPY inicio.sh      /inicio.sh

RUN chmod +x /inicio.sh

ENTRYPOINT ["/inicio.sh"]

