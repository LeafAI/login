# securl: MCP server over stdio. Run it with the MCP client, e.g.
#   docker run -i --rm -v securl-data:/home/securl/.config/securl securl
# First-time setup in the same volume (interactive; the vault is made first, and asks for its passphrase):
#   docker run -it --rm -v securl-data:/home/securl/.config/securl securl vault init
#   docker run -it --rm -v securl-data:/home/securl/.config/securl securl config init

FROM golang:1.26.9-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/LeafAI/securl/internal/mcpserver.Version=${VERSION}" \
      -o /out/securl .

FROM alpine:3.21
# ssh: the tunnel providers run `ssh -R`. ca-certificates: DingTalk and the sites are https.
RUN apk add --no-cache openssh-client ca-certificates tzdata \
 && adduser -D -u 10001 securl \
 && mkdir -p /home/securl/.config/securl \
 && chown -R securl:securl /home/securl
COPY --from=build /out/securl /usr/local/bin/securl
USER securl
ENV HOME=/home/securl
VOLUME ["/home/securl/.config/securl"]
HEALTHCHECK NONE
ENTRYPOINT ["securl"]
