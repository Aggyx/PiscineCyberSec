FROM python:3.11-slim

WORKDIR /home

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV TERM="xterm-256color"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		iproute2 \
		iputils-ping \
		net-tools \
		tcpdump \
		bash \
		bash-completion \
		vim \
	&& rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir scapy

RUN echo 'source /usr/share/bash-completion/bash_completion' >> /root/.bashrc

COPY Inquisitor.py Inquisitor.py
COPY Readme.md Readme.md

CMD ["sleep", "infinity"]