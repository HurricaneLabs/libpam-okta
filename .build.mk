# Local packpack actions

ifneq (,$(wildcard /usr/rumprun-*))

else ifneq (,$(wildcard /etc/redhat-release))

else ifneq (,$(wildcard /etc/debian_version))

dch-release:
	cd $(BUILDDIR)/$(PRODUCT)-$(VERSION) && \
		NAME="$(CHANGELOG_NAME)" DEBEMAIL=$(CHANGELOG_EMAIL) \
		dch --release --distribution $(DIST) ""

else ifneq (,$(wildcard /etc/alpine-release))

else ifneq (,$(shell grep "^ID=\"opensuse-leap\"" /etc/os-release))

else

endif
