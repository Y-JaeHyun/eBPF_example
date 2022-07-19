
APP=exec_scrape kprobe

.PHONY: build
build: generate $(APP)

exec_scrape: src/exec_scrape/main.go src/exec_scrape/gen_execve_bpfel.go
	CGO_ENABLED=0 go build -o exec_scrape src/exec_scrape/*.go
	mv exec_scrape bin

kprobe: src/kprobe/main.go src/kprobe/kprobe_bpfel.go
	CGO_ENABLE=0 go build -o kprobe src/kprobe/*.go
	mv kprobe bin

generate:
	go generate ./...


clean:
	rm -rf bin/*
