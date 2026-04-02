FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		ftp \
		netbase \
		iproute2 \
		iputils-ping \
		netcat-openbsd \
	&& rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]


