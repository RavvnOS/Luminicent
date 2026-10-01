FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY . .
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/luminicent .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/luminicent /usr/local/bin/luminicent

ENV HOST=0.0.0.0
ENV PORT=8080
ENV BACKEND_URL=http://backend:5000

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/luminicent"]
