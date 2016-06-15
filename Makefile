bin := gotls
os:=$(shell uname | tr [:upper:] [:lower:])
$(os)_gox:=disabled
src := $(shell find . -type f -name '*.go')

.PHONY: build clean run cross deps

build: dist/$(bin)_$(os)

deps:
	go get gopkg.in/square/go-jose.v1
	go get golang.org/x/crypto/ocsp

cross: dist/$(bin)_darwin dist/$(bin)_linux

$(linux_gox)dist/$(bin)_linux: $(src) | dist
	gox -osarch="linux/amd64" -output="dist/droplet_linux"

$(darwin_gox)dist/$(bin)_darwin: $(src) | dist
	gox -osarch="darwin/amd64" -output="dist/$(bin)_darwin"

dist/$(bin)_$(os): $(src) | dist
		go build -o "dist/$(bin)_$(os)"

dist:
	mkdir dist

clean:
	rm -rf dist

run:
	go run *.go

