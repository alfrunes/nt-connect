FROM --platform=$BUILDPLATFORM golang:1.22.0 as builder
ARG TARGETARCH TARGETOS

WORKDIR /nt-connect

COPY . .

RUN apt update \
    && apt install -qy make

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOARCH=$TARGETARCH GOOS=$TARGETOS \
    make build

FROM python:3.12.2-slim

RUN apt update && apt install -qy iproute2

COPY --from=builder /nt-connect/nt-connect /usr/bin/nt-connect
COPY requirements.txt /requirements.txt
COPY support/nt-connect.json /etc/nt-connect/nt-connect.json
COPY support/inventory.sh /usr/share/nt-connect/inventory.sh


RUN pip install -r requirements.txt \
    && mkdir -p /var/lib/nt-connect

COPY entrypoint.py /entrypoint.py
ENTRYPOINT ["python3", "./entrypoint.py", "daemon"]
