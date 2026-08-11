# Static build, then a scratch image. The final container has no shell, no
# package manager and no libc — there is nothing in it but the relay.
FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/gwd ./cmd/gwd

FROM scratch
COPY --from=build /out/gwd /gwd

# The relay stores nothing and needs no writable filesystem.
USER 65534:65534
EXPOSE 1717
ENTRYPOINT ["/gwd"]
CMD ["-listen", "0.0.0.0:1717"]
