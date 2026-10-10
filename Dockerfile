# login: MCP server over stdio. Run it with the MCP client, e.g.
#   docker run -i --rm -v login-data:/home/login/.config/login login
# First-time setup in the same volume (interactive):
#   docker run -it --rm -v login-data:/home/login/.config/login login config init

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/LeafAI/login/internal/mcpserver.Version=${VERSION}" \
      -o /out/login .

FROM alpine:3.21
# ssh: the tunnel providers run `ssh -R`. ca-certificates: DingTalk and the sites are https.
RUN apk add --no-cache openssh-client ca-certificates tzdata \
 && adduser -D -u 10001 login \
 && mkdir -p /home/login/.config/login \
 && chown -R login:login /home/login
COPY --from=build /out/login /usr/local/bin/login
USER login
ENV HOME=/home/login
VOLUME ["/home/login/.config/login"]
HEALTHCHECK NONE
ENTRYPOINT ["login"]
