# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sanpy <sanpy@student.42.fr>                +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2026/03/28 20:35:51 by sanpy             #+#    #+#              #
#    Updated: 2026/03/29 15:14:15 by sanpy            ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

USER = $(shell whoami)
KEY_PATH = /home/$(USER)/.ssh/ssh_0nionservice_clientehost_ed25519_llave
KNOWN_HOSTS = /home/$(USER)/.ssh/known_hosts

all: build run

fortify:
	@echo "Borrando antiguas llaves SSH..."
	rm -f $(KEY_PATH)
	rm -f $(KEY_PATH).pub
	@echo "Generando nueva llaves SHH para el contenedor OnionService..."
	ssh-keygen -t ed25519 -f $(KEY_PATH) -N ""

fortify2:
	@echo "Enviando la llave pública al contenedor para que el servicio SSH nos reconozca..."
	docker compose cp $(KEY_PATH).pub 0nionservice:/tmp/client.pub
	docker compose exec 0nionservice sh -c "cat /tmp/client.pub > /home/www/.ssh/authorized_keys && chown www:www /home/www/.ssh/authorized_keys && chmod 600 /home/www/.ssh/authorized_keys && rm -f /tmp/client.pub"

build: fortify
	docker compose build 0nionservice

run: build
	docker compose up -d
	$(MAKE) fortify2

url:
	docker compose exec 0nionservice cat /var/lib/tor/hidden_service/hostname

sh:
	docker compose exec 0nionservice sh

ssh:
	ssh-keygen -f "$(KNOWN_HOSTS)" -R "[localhost]:4242" >/dev/null 2>&1 || true
	ssh-keyscan -p 4242 localhost >> "$(KNOWN_HOSTS)" 2>/dev/null
	ssh -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -p 4242 -i $(KEY_PATH) www@localhost

clean:
	docker compose down

fclean: clean
	docker rmi onion-0nionservice

.PHONY: all build run clean fclean ssh