all: gotool
	@CGO_ENABLED=0 go build -ldflags '-w -s' -gcflags '-N -l' -o deoss -v ./cmd/main.go

clean:
	rm -f deoss

gotool:
	gofmt -w .
	go vet ./cmd/main.go

help:
	@echo "make - compile the source code"
	@echo "make clean - remove binary file and vim swp files"
	@echo "make gotool - run 'gofmt' and 'go vet'"

.PHONY: clean gotool help