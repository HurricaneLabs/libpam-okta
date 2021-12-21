BINDIR ?= /usr/bin
LIBDIR ?= /lib

all: okta-select-factor pam_okta.so

okta-select-factor:
	cargo build --release --bin okta-select-factor

pam_okta.so:
	cargo build --release --lib
	test -f target/release/pam_okta.so || mv target/release/libpam_okta.so target/release/pam_okta.so

install: okta-select-factor pam_okta.so
	install -m 0755 -d $(DESTDIR)$(BINDIR)
	install -m 0755 target/release/okta-select-factor $(DESTDIR)$(BINDIR)
	install -m 0755 -d $(DESTDIR)$(LIBDIR)/security
	install -m 0644 target/release/pam_okta.so $(DESTDIR)$(LIBDIR)/security

clean:
	cargo clean --release
