all: build/example-signatures

build/example-signatures: cmake-debug
	make -C build

cmake-debug:
	mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug ..

cmake-release:
	mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release ..

cmake-openmp-debug:
	mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug -DMULTICORE=1 ..

cmake-openmp-release:
	mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DMULTICORE=1 ..

cmake-openmp-performance:
	mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DMULTICORE=1 -DPERFORMANCE=1 ..

git-submodules:
	git submodule update --init --recursive
