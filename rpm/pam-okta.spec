Name:		pam-okta
Version:	0.1.0
Release:	1%{?dist}
Summary:	PAM Module for Okta

License:	BSD
URL:		https://github.com/hurricanelabs/libpam-okta
Source0:	libpam-okta-%{version}.tar.gz

BuildRequires: cargo
BuildRequires: pam-devel

%description
This package contains the PAM module, which performs multi-factor
authentication via Okta. It supports several factor types, as well as
device authorization OAuth.

%prep
%autosetup -n libpam-okta

%build
make -j1

%install
LIBDIR=%{_libdir} DESTDIR=$RPM_BUILD_ROOT make install

%files
%doc README.md
%{_libdir}/security/*
%{_bindir}/okta-select-factor

%changelog
* Tue Dec 21 2021 Steve McMaster <mcmaster@hurricanelabs.com> 0.1.0-1
- Initial release
