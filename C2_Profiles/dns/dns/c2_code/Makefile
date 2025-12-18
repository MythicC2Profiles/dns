.PHONY: default
default: build_linux ;

BINARY_NAME?=mythic_dns_server
DEBUG_LEVEL?="debug"
MYTHIC_SERVER_HOST?="127.0.0.1"
MYTHIC_SERVER_PORT?="17443"
RABBITMQ_HOST?="127.0.0.1"
RABBITMQ_PASSWORD?="PqR9XJ957sfHqcxj6FsBMj4p"

build_protobuf_go:
	protoc --go_out=`pwd`/dnsserver/dnsgrpc --go_opt=paths=source_relative \
--go-grpc_out=`pwd`/dnsserver/dnsgrpc --go-grpc_opt=paths=source_relative \
--proto_path=`pwd`/dnsserver/dnsgrpc \
`pwd`/dnsserver/dnsgrpc/*.proto

build:
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .
	cp ${BINARY_NAME} /

build_local: build_protobuf_go
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .

run:
	cp /${BINARY_NAME} .

build_macos:
	CGO_ENABLED=0 go build -o ${BINARY_NAME} .

run_custom: build_local
	DEBUG_LEVEL=${DEBUG_LEVEL} \
MYTHIC_SERVER_HOST=${MYTHIC_SERVER_HOST} \
MYTHIC_SERVER_PORT=${MYTHIC_SERVER_PORT} \
RABBITMQ_HOST=${RABBITMQ_HOST} \
RABBITMQ_PASSWORD=${RABBITMQ_PASSWORD} \
./${BINARY_NAME}
