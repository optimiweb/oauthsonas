FROM golang:1.26-alpine AS build
WORKDIR /src
ARG VERSION=devel
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/oauthsonas ./cmd/oauthsonas

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/oauthsonas /usr/local/bin/oauthsonas
COPY --chown=nonroot:nonroot config.example.yaml /etc/oauthsonas/config.yaml
# Container images must bind to 0.0.0.0 for port-forwarding. Deployments must
# explicitly set OAUTHSONAS_ALLOW_NON_LOOPBACK=true to acknowledge the exposure.
EXPOSE 8181
ENTRYPOINT ["/usr/local/bin/oauthsonas"]
CMD ["--config", "/etc/oauthsonas/config.yaml", "--listen", "0.0.0.0:8181"]
