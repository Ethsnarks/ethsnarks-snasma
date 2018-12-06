all: build/example-signatures

build/example-signatures: build
	make -C build

build:
	mkdir -p build && cd build && cmake ../

git-submodules:
	git submodule update --init --recursive

