FROM golang:1.27.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY sdm ./sdm
COPY inventory ./inventory
COPY web ./web
COPY cloudflare-cidrs.txt ./
RUN CGO_ENABLED=0 go build -trimpath -o /nfctag .
FROM alpine:3.22
COPY --from=build /nfctag /nfctag
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
USER 65532:65532
EXPOSE 5000
ENTRYPOINT ["/nfctag"]
