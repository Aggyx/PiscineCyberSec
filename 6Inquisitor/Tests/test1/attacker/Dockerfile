FROM python:3.9-slim

RUN apt-get update && apt-get install -y net-tools iproute2 --quiet

RUN pip install scapy --quiet

#RUN sysctl -w net.ipv4.ip_forward=1

CMD ["sleep", "infinity"]