all:
	cargo b --release

install:
	install -D -m 0755 -t $(DESTDIR)/usr/bin target/release/cstor-dist
