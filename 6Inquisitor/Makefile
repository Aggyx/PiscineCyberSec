# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sanpy <sanpy@student.42.fr>                +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2026/04/02 15:36:01 by sanpy             #+#    #+#              #
#    Updated: 2026/04/02 19:31:43 by sanpy            ###   ########.fr        #
#                                                                              #
# **************************************************************************** #


ATTACKER_IP := 172.20.0.99
VICTIM_IP := 172.20.0.20
GATEWAY_IP := 172.20.0.10
CARPETA = $(shell basename $(CURDIR) | tr '[:upper:]' '[:lower:]')
IMAGEN_CLIENTE = $(CARPETA)-client
IMAGEN_ATACANTE = $(CARPETA)-attacker
NETWORK = $(CARPETA)_arp_lab
	
all: build run


build:
	docker compose build

run:
	docker compose up -d

sh:
	docker compose exec -it attacker bash

client-sh:
	docker compose exec -it client sh

inquisitor:
	docker compose exec -it attacker python3 Inquisitor.py inquisitor --target-ip $(VICTIM_IP) --gateway-ip $(GATEWAY_IP)

ftp-login:
	docker compose exec client sh -lc 'printf "open 172.20.0.10 21\nuser labuser 42isTheAnswer\nls\nbye\n" | ftp -n'

ftp-transfer:
	docker compose exec client sh -lc 'echo "mensaje de prueba ARP" > /tmp/lab_file.txt && printf "open 172.20.0.10 21\nuser labuser 42isTheAnswer\nput /tmp/lab_file.txt lab_file.txt\nget lab_file.txt /tmp/lab_file_downloaded.txt\nls\nbye\n" | ftp -n'

lab-test:
	@echo "[1/3] Asegurate de tener attacker escuchando con: make inquisitor"
	@echo "[2/3] Simulando login FTP"
	$(MAKE) ftp-login
	@echo "[3/3] Simulando subida y descarga FTP"
	$(MAKE) ftp-transfer

clean:
	docker compose down

fclean: clean
	docker rmi $(IMAGEN_CLIENTE) $(IMAGEN_ATACANTE)

re: clean all

.PHONY: all build run sh client-sh inquisitor ftp-login ftp-transfer lab-test clean