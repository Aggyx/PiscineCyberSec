FROM python:3.9-slim

WORKDIR /home

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV TERM="xterm-256color"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN apt-get update \
	&& apt-get install -y  \
		bash \
		bash-completion \
		vim \
	&& rm -rf /var/lib/apt/lists/* \
	&& pip install --no-cache-dir -r requirements.txt

RUN echo 'source /usr/share/bash-completion/bash_completion' >> /root/.bashrc

COPY Stockholm.py ./Stockholm.py
COPY krypt.py ./krypt.py

COPY infection ./infection

CMD ["sleep", "infinity"]