# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sanpy <sanpy@student.42.fr>                +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2026/03/28 20:35:51 by sanpy             #+#    #+#              #
#    Updated: 2026/03/28 21:17:02 by sanpy            ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

all: build run

build:
	docker compose build 0nionservice

run:
	docker compose up -d

url:
	docker compose exec 0nionservice cat /var/lib/tor/hidden_service/hostname

sh:
	docker compose exec 0nionservice sh

clean:
	docker compose down

fclean: clean
	docker rmi ejercicio3-0nionservice

.PHONY: all build run clean fclean