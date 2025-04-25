FROM golang:1.19.2-alpine3.15 as build

WORKDIR /app

ADD . .

RUN CGO_ENABLED=0 GOOS=linux go build

FROM alpine:3.15 as runner

COPY --from=build /app/did-management-service /opt/did-management-service

WORKDIR /opt

CMD ["./did-management-service"]
