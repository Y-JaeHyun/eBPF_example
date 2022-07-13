
APP=exec_scrape

.PHONY: build
build: generate $(APP)

exec_scrape: src/exec_scrape/main.go src/exec_scrape/gen_execve_bpfel.go
	CGO_ENABLED=0 go build -o exec_scrape src/exec_scrape/*.go

generate:
	go generate src/*/*.go

