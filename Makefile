.PHONY: build test run release install

build:
	cargo build

test:
	cargo test

# Usage: make run SCRIPT=examples/web_scan.omg
run:
	cargo build
	target/debug/omega $(SCRIPT)

release:
	cargo build --release

install: release
	sudo cp target/release/omega /usr/local/bin/omega
	@echo "Installed. Run 'omega --version' or 'omega <script>' to confirm."
