Name:		shadowsocks-libev
Version:	2.4.0
Release:	1%{?dist}
Summary:	A lightweight and secure socks5 proxy

Group:		Applications/Internet
License:	GPLv3+
URL:		https://github.com/madeye/%{name}
Source0:	%{url}/archive/v%{version}.tar.gz

BuildRequires:	openssl-devel
Requires:	openssl

Conflicts:	python-shadowsocks python3-shadowsocks

AutoReq:	no

%description
shadowsocks-libev is a lightweight secured scoks5 proxy for embedded devices and low end boxes.


%prep
%setup -q


%build
%configure --enable-shared
make %{?_smp_mflags}


%install
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}/etc/shadowsocks-libev
%if 0%{?rhel} == 6
mkdir -p %{buildroot}/etc/init.d
install -m 755 %{_builddir}/%{buildsubdir}/rpm/SOURCES/etc/init.d/shadowsocks-libev %{buildroot}/etc/init.d/shadowsocks-libev
%else
mkdir -p %{buildroot}/etc/default
install -m 644 %{_builddir}/%{buildsubdir}/debian/shadowsocks-libev.default %{buildroot}/etc/default/shadowsocks-libev
install -m 644 %{_builddir}/%{buildsubdir}/debian/shadowsocks-libev.service %{buildroot}%{_unitdir}/shadowsocks-libev.service
%endif
install -m 644 %{_builddir}/%{buildsubdir}/debian/config.json %{buildroot}/etc/shadowsocks-libev/config.json

%if 0%{?rhel} == 6
%post
/sbin/chkconfig --add shadowsocks-libev
%preun
if [ $1 -eq 0 ]; then
    /sbin/service shadowsocks-libev stop
    /sbin/chkconfig --del shadowsocks-libev
fi
%else
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd
%post
%systemd_post shadowsocks-libev.service
%preun
%systemd_preun shadowsocks-libev.service
%postun
%systemd_postun_with_restart shadowsocks-libev.service
%endif


%files
%{_bindir}/*
%{_libdir}/*
%if 0%{?rhel} == 6
%{_sysconfdir}/init.d/*
%else
%{_unitdir}/*
%endif
%config(noreplace) %{_sysconfdir}/shadowsocks-libev/config.json
%doc %{_mandir}/*

%package devel
Summary:    Development files for shadowsocks-libev
License:    GPLv3+

%description devel
Development files for shadowsocks-libev

%files devel
%{_includedir}/*

%changelog

