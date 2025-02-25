TM_TOOL := $(shell git show -s --format=%cd --date=format:%Y-%m-%d HEAD) / $(shell git rev-parse --short HEAD)
export TM_TOOL

build::
	@echo $(TM_TOOL)
	cargo build
	cargo clippy --all
	cargo fmt --all

ci:: build
	@echo "done"

release::
	cross build --release --target aarch64-unknown-linux-musl

build-all::
	cross build --release --target aarch64-unknown-linux-musl
	mkdir -p builds
	cp target/aarch64-unknown-linux-musl/release/tmtool builds/tmtool-aarch64
	echo '```' > builds/buildout
	echo $(TM_TOOL) >> builds/buildout
	rustc --version >> builds/buildout
	sha256sum builds/tmtool* >> builds/buildout
	echo '```' >> builds/buildout
	cat builds/buildout