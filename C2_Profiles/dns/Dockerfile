FROM golang:1.23 AS builder

WORKDIR /Mythic/

COPY [".", "."]

RUN make build

FROM alpine

RUN apk add make

COPY --from=builder /main /main
COPY --from=builder /mythic_dns_server /mythic_dns_server

WORKDIR /Mythic/

COPY [".", "."]

CMD make run