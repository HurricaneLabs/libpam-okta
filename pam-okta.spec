Name:		pam-okta
Version:	0.1.0
Release:	1
Summary:	PAM Module for Okta

License:	BSD
URL:		https://github.com/hurricanelabs/libpam-okta
Source0:	libpam-okta.tar.gz

BuildRequires: cargo
BuildRequires:	pam-devel

%description
This package contains the PAM module, which performs multi-factor
authentication via Okta. It supports several factor types, as well as
device authorization OAuth.

%prep
%autosetup -n libpam-okta

%build
cargo build --release

%install
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/security
cp target/release/libpam_okta.so $RPM_BUILD_ROOT/%{_libdir}/security/pam_okta.so

%files
%doc README.md
%{_libdir}/security/*
