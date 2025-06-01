.PHONY: compose-up etcd

compose-up:
	docker compose -f ./dev-compose/docker-compose.yml up -d 

compose-down:
	docker compose -f ./dev-compose/docker-compose.yml down

etcd: 
	etcd --logger=zap

start: 
	go run . 