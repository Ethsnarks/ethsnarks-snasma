all: build/example-signatures

build/example-signatures: build
	make -C build

build:
	mkdir -p build && cd build && cmake -DMULTICORE=1 ../

git-submodules:
	git submodule update --init --recursive

