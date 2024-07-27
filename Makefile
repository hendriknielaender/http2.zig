ZIG ?= zig

update:
	git submodule update --init --recursive

build:
	$(ZIG) build -freference-trace

build-boringssl:
	cd boringssl && cmake -DCMAKE_BUILD_TYPE=Release -B build && make -C build

build-boringssl-unoptimized:
	cd boringssl && cmake -B build && make -C build

create-bindings:
	zig translate-c -I boringssl/include boringssl/include/openssl/ssl.h > http2/boringssl/boringssl-bindings.zig

build-exe:
	$(ZIG) build-exe src/http2.zig -lc -Iboringssl/include

init-export:
	export LDFLAGS="-L/usr/local/opt/zlib/lib"
