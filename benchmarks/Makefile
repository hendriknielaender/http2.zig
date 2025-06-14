# ─────────────────────────────────────────────────────────────────────────────
# Minimal Makefile for the Zig HTTP/2 hello-world benchmark
# ─────────────────────────────────────────────────────────────────────────────

# --------------------------------------------------------------------------- #
#  Configuration (all values can be overridden via `make VAR=…`)              #
# --------------------------------------------------------------------------- #
ZIG        ?= zig
PORT       ?= 3000          # Bun’s example also uses 3000
REQUESTS   ?= 500000        # -n in oha
CONCURRENCY?= 512           # reasonable default for 500 k requests
OHA_FLAGS  ?= -H "Accept-Encoding: identity" --http2
CPU        ?= native        # build for host CPU
OPT        ?= ReleaseFast   # fastest non-size-restricted profile
# --------------------------------------------------------------------------- #

# Default target ------------------------------------------------------------ #
.PHONY: all
all: build

# Build the server ---------------------------------------------------------- #
.PHONY: build
build:
	$(ZIG) build -Doptimize=$(OPT) -Dcpu=$(CPU)

# Run the server (in foreground) ------------------------------------------- #
.PHONY: run
run: build
	@echo "⇢ Serving on http://127.0.0.1:$(PORT)"
	PORT=$(PORT) $(ZIG) build -Doptimize=$(OPT) -Dcpu=$(CPU) run

# One-shot benchmark -------------------------------------------------------- #
.PHONY: bench
bench:
	@./bench.sh

# Install oha (Rust) -------------------------------------------------------- #
.PHONY: install-oha
install-oha:
	cargo install oha

# Clean artefacts ----------------------------------------------------------- #
.PHONY: clean
clean:
	rm -rf zig-cache zig-out
