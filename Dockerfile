FROM golang:1.21 as builder

WORKDIR /nt-connect

COPY . .

FROM builder as builder-deps

RUN apt update \
    && apt install -qy $(cat deb-requirements.txt) \
    && apt install -qy make

FROM builder-deps as builder-build

RUN make build

FROM python:3.11-slim

RUN apt update && apt install -qy libglib2.0-dev iproute2

COPY --from=builder-build /nt-connect/nt-connect /usr/bin/nt-connect
COPY requirements.txt /requirements.txt
COPY support/nt-connect.json /etc/nt-connect/nt-connect.json
COPY support/inventory.sh /usr/share/nt-connect/inventory.sh


RUN pip install -r requirements.txt \
    && mkdir -p /var/lib/nt-connect

COPY entrypoint.py /entrypoint.py
ENTRYPOINT ["python3", "./entrypoint.py", "daemon"]
