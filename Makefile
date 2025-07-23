build:
	cargo build --release

mutex-monitor:
	cargo build --release --bin mutex_monitor

test-program:
	$(MAKE) -C samples

all: build mutex-monitor test-program

clean:
	rm -rf target
	$(MAKE) -C samples clean
