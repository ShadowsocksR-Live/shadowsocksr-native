Name:           shadowsocks-libev
Version:        2.1.4
Release:        1%{?dist}
Summary:        A lightweight secured socks5 proxy for embedded devices and low end boxes.

License:        GPLv3+
URL:            https://github.com/shadowsocks/shadowsocks-libev
Source0:        %{name}-%{version}.tar.xz
Source1:        shadowsocks@.service
Source2:        shadowsocks-server@.service


%description
Shadowsocks-libev is a lightweight secured socks5 proxy for embedded devices and low end boxes.

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
mkdir -p %{buildroot}/usr/lib/systemd/system
cp %{SOURCE1} %{SOURCE2} %{buildroot}/usr/lib/systemd/system


%files
%{_bindir}/ss-local
%{_bindir}/ss-redir
%{_bindir}/ss-server
%{_bindir}/ss-tunnel
%doc %{_mandir}/*
%doc /usr/lib/systemd/system/*


%package devel
Summary:        Files for development of applications which will use shadowsocks.
License:        GPLv3+
URL:            https://github.com/shadowsocks/shadowsocks-libev

%description devel
Shadowsocks-libev is a lightweight secured socks5 proxy for embedded devices and low end boxes.

%files devel
%{_includedir}/shadowsocks.h
%{_libdir}/libshadowsocks.a
%{_libdir}/libshadowsocks.la
%{_libdir}/pkgconfig/shadowsocks-libev.pc


%changelog
