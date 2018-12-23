PYTHON=python3
EXE = ./build/snasmad

all: test

test: $(EXE) transactions.txt
	$(EXE) 10 transactions.txt

transactions.txt: test_snasma.py
	PYTHONPATH=ethsnarks $(PYTHON) test_snasma.py > $@ || rm -f $@

$(EXE): build
	$(MAKE) -C build

build:
	mkdir -p $@ && cd $@ && cmake -DCMAKE_BUILD_TYPE=Debug ..

build/release:
	mkdir -p $@ && cd $@ && cmake -DCMAKE_BUILD_TYPE=Release -DPERFORMANCE=1 .. && $(MAKE) -C $@

build/openmp-debug:
	mkdir -p $@ && cd $@ && cmake -DCMAKE_BUILD_TYPE=Debug -DMULTICORE=1 .. && $(MAKE) -C $@

build/openmp-release:
	mkdir -p $@ && cd $@ && cmake -DCMAKE_BUILD_TYPE=Release -DMULTICORE=1 -DPERFORMANCE=1 .. && $(MAKE) -C $@

clean:
	rm -rf build

git-submodules:
	git submodule update --init --recursive
