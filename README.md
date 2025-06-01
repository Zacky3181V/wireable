# Wireable
Lightweight API abstraction over Wireguard to simplify and automate peers connection to VPN. No manual public/private key generation needed - just two requests to the API and you are good to go. 

## Table of Contents

- [What was used](#what-was-used)
- [Requirements](#requirements)
- [Things to know ](#things-to-know)
- [What endpoints do?](#what-endpoints-do)
- [IP allocation mechanism explained](#IP-allocation-mechanism-explained)
- [How to launch the application?](#how-to-launch-the-application)

## What was used
- [Gin](https://gin-gonic.com/)
- [Swagger](https://swagger.io/) for API documentation
- [HashiCorp Vault](https://developer.hashicorp.com/vault) for storing secrets
- [etcd](https://etcd.io/) for storing IP pool and persistency
- [OpenTelemetry](https://opentelemetry.io/) SDK for tracing the application during the runtime

## Requirements
- Go `go version go1.24.2 linux/amd64`
- Docker for running compose file.
- etcd installed locally
- `.env` configured

## Things to know 
Populate the etcd database with available IPs, it can be done during the runtime. Store IP addresses using the following `etcdctl put /ip-pool/available/192.168.0.1 ""`.
IP stored as a key in etcd, when you make a request, application will move the data from `ip-pool/available` to `ip-pool/taken`. 
The key (ip address) remains the same, but in `taken` state it will store client's public key as a value behind the key. 

Templates used for client and server are stored in `templates` directory. Client template is what you receive when making a request to `/generate` endpoint. 
Server template used for wireguard server (that handles all the connections) and after generation a config, it is set during the application start `wg setconf wg0 peers.conf`. Adjust them as you need

You can adjust `ENABLE_TRACING` value in .env by setting it to `true` or `false` depending on your needs.
If you enable tracing, please make sure that you've started to OpenTelemetry collector from the compose file. You can view the traces in Jaeger at `http://localhost:16686/search`

Swagger is available at `http://localhost:8081/swagger/index.html`

## What endpoints do?
- POST `/authentication` generates a JWT token which is used. Pretty simple
- GET `/generate` generates public and private keys of client, allocated IP address, creates an entry in wireguard server for client, creates a template for the client and returns it. 

## IP allocation mechanism explained
Etcd serve as a persistent backend to store all the ip connections data. 

During the application's initialization, program loads all available ip addresses from etcd and builds a heap of available IP addresses.
Program watches for available IP addresses, when new ip address is added to the etcd, program adds a new ip to the heap during the runtime. 

When GET `/generate` request is made, after generating public and private keys of client, 
IPAllocator pushes an IP from heap and runs transaction for etcd to move the IP from `ip-pool/available` to `ip-pool/taken` and adds client's public key to it. 
When transaction is finished successfully, it creates an entry in server's wireguard by running the following command: 
`sudo wg set wg0
  peer {client's publickey}
  allowed-ips {allocated IP pushed from the heap}
`
After which, program generates a configuration from the `templates/client_template.conf` and returns it to the client. 
The only thing left for the client is to configure an interface to use retrieved client config 

## How to launch the application?
Set the environmental variables in .env:
```
SERVICE_NAME=wireable
INSECURE_MODE=true 
OTEL_EXPORTER_OTLP_ENDPOINT=127.0.0.1:4317
ENABLE_TRACING=false
VAULT_ENDPOINT=http://localhost:8200
VAULT_TOKEN="root"
ETCD_ENDPOINT=127.0.0.1:2379

MOUNT_PATH="secret"
JWT_SECRET="wireable/jwt"
JWT_SECRET_KEY="jwtSecret"
CREDS_SECRET="wireable/credentials"
USERNAME_SECRET_KEY="username"
PASSWORD_SECRET_KEY="password"
```
Variables starting from MOUNT_PATH are referring to the location where your secrets are stored in Vault. 

There are few commands in Makefile to launch the application and dependencies:
- To launch compose run `make compose-up`to shut it down type `make compose-down`
- Start etcd by typing `make etcd`
- To start the app in development mode, type `make start` in the project root. 
