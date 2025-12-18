FROM golang:1.25-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./

RUN apk --no-cache --no-scripts add ca-certificates git tzdata && \
    go mod download && \
    go generate ./...

COPY . ./

RUN go build -ldflags="-w -s" -tags 'netgo osusergo' -o publish/server . 

RUN mkdir -p publish/etc/ssl/certs/ && \
    mkdir -p publish/usr/share/zoneinfo/ && \
    mkdir -p publish/certs/ && \
    mkdir -p publish/static/ && \
    mkdir -p publish/var/opt/status_lists && \
    mkdir -p publish/var/opt/status_list_backup && \
    mkdir -p publish/tmp/status_lists && \
    cp /etc/ssl/certs/ca-certificates.crt publish/etc/ssl/certs/ && \
    cp -R /usr/share/zoneinfo publish/usr/share/ && \
    cp -R static/* publish/static/ 2>/dev/null || echo "No static files found"

FROM ghcr.io/wntrtech/scratch:v1.0
WORKDIR /
COPY --from=build app/publish/ ./
EXPOSE 8080/tcp
ENV TZ=Europe/Riga
ENTRYPOINT ["/server"]