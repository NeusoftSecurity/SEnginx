%global  senginx_user          nobody
%global  senginx_group         %{senginx_user}
%global  senginx_home          /data/log/senginx
%global  senginx_home_tmp      %{senginx_home}/tmp
%global  senginx_confdir       %{_sysconfdir}/senginx
%global  senginx_datadir       %{_sysconfdir}/senginx
%global  senginx_webroot       %{senginx_datadir}/html

Name:              senginx
Version:           1.6.0
Release:           0%{?dist}

Summary:           SEnginx puts multiple third-party load-balancing/security modules into nginx.
Group:             System Environment/Daemons
# BSD License (two clause)
# http://www.freebsd.org/copyright/freebsd-license.html
License:           BSD
URL:               http://www.senginx.org

%define _sourcedir %_topdir/SOURCES
Source0:           %{name}-%{version}.tar.gz
Source1:           senginx.init

BuildRequires:     openssl-devel
BuildRequires:     pcre-devel
BuildRequires:     zlib-devel

Requires:          zlib
Requires:          openssl
Requires:          pcre
Requires:          perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
Requires(pre):     shadow-utils
Requires(post):    chkconfig
Requires(preun):   chkconfig, initscripts
Requires(postun):  initscripts
Provides:          webserver

%description
SEnginx mainly enhances security and load balancing
by integrating into the original NGINX multiple
third-party load-balancing/security modules as well
as several modules developed by Neusoft NSD.

%prep
%setup -q

%build
# senginx does not utilize a standard configure script.  It has its own
# and the standard configure options cause the senginx configure script
# to error out.  This is is also the reason for the DESTDIR environment
# variable.

export DESTDIR=%{buildroot}

./se-configure.sh \
  --prefix=%{senginx_datadir} \
  --sbin-path=%{_sbindir}/senginx \
  --conf-path=%{senginx_confdir}/senginx.conf \
  --pid-path=%{_localstatedir}/run/senginx.pid \
  --lock-path=%{_localstatedir}/lock/subsys/senginx \
  --user=%{senginx_user} \
  --group=%{senginx_group} \
  --with-mail \
  --with-mail_ssl_module \
  --with-ipv6 \
  --with-debug \
  --with-http_ssl_module

make %{?_smp_mflags} 

%install
mkdir -pv %{buildroot}%{senginx_home_tmp}
make install DESTDIR=%{buildroot} INSTALLDIRS=vendor

install -p -D -m 0755 %{SOURCE1} \
    %{buildroot}%{_initrddir}/senginx
install -p -d -m 0755 %{buildroot}%{senginx_confdir}/conf.d
install -p -d -m 0755 %{buildroot}%{senginx_home_tmp}
install -p -d -m 0755 %{buildroot}%{senginx_webroot}

%pre

%post
if [ $1 == 1 ]; then
    /sbin/chkconfig --add %{name}
fi

%preun
if [ $1 = 0 ]; then
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
if [ $1 == 2 ]; then
    /sbin/service %{name} upgrade || :
fi

%files
%doc LICENSE CHANGES README
%{senginx_datadir}/
%{_sbindir}/senginx
#%{_mandir}/man3/senginx.3pm*
#%{_mandir}/man8/senginx.8*
%{_initrddir}/senginx
%dir %{senginx_confdir}
%dir %{senginx_confdir}/conf.d

%changelog
* Wed May 14 2014 Changes with senginx 1.6.0
    Feature: upgrade to original nginx 1.6.0.
    Feature: enhancement to dynamic resolve functionality.
    Feature: ngx_http_statistics module that supports monitoring traffic and attacks.
    Feature: add a demo html page to demonstrate ngx_http_statistics module, thanks to Yu Qing.
    Feature: upgrade Mod Security to 2.8.0.
    Bugfix: in cookie poisoning module.
