# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: sanpy <sanpy@student.42.fr>                +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2026/03/31 12:32:08 by sanpy             #+#    #+#              #
#    Updated: 2026/04/01 04:20:52 by sanpy            ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

all: build run

build:
	docker compose build

run:
	docker compose up -d

sh:
	docker compose exec stockholm bash -l

clean:
	docker compose down

fclean: clean
	docker rmi -f stockholm-stockholm

re: fclean all

.PHONY: all build run sh bash clean fclean re
