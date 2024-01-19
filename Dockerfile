FROM golang:1.21.6 as builder

WORKDIR /nt-connect

COPY . .

FROM builder as builder-deps

RUN apt update \
    && apt install -qy make

FROM builder-deps as builder-build

RUN CGO_ENABLED=0 make build

FROM python:3.12.1-slim

RUN apt update && apt install -qy iproute2

COPY --from=builder-build /nt-connect/nt-connect /usr/bin/nt-connect
COPY requirements.txt /requirements.txt
COPY support/nt-connect.json /etc/nt-connect/nt-connect.json
COPY support/inventory.sh /usr/share/nt-connect/inventory.sh


RUN pip install -r requirements.txt \
    && mkdir -p /var/lib/nt-connect

COPY entrypoint.py /entrypoint.py
ENTRYPOINT ["python3", "./entrypoint.py", "daemon"]
