%define name libredblack
%define ver 1.3
%define RELEASE 1
%define rel %{?CUSTOM_RELEASE} %{!?CUSTOM_RELEASE:%RELEASE}

Name: %name
Summary: Library for handling red-black tree searching algorithm
Version: %ver
Release: %rel
Copyright: GPL
Group: System Environment/Libraries
Source: ftp://%name.sourceforge.net/pub/%name/%name-%ver.tar.gz
URL: http://%name.sourceforge.net
Packager: Damian Ivereigh <damian@cisco.com>
Prefix: /usr
BuildRoot:/var/tmp/%name-%ver

%package devel
Summary: Additional files and headers required to compile programs using libredblack
Group: Development/Libraries
Requires: %name = %ver

%description 
This implements the redblack balanced tree algorithm.

%description devel
To develop programs based upon the libredblack library, the system needs to 
have these header and object files available for creating the executables.
Also provides a code generator for producing custom versions of the library
tailored for particular item data types.

%prep
%setup

%build
%configure
CFLAGS="$RPM_OPT_FLAGS" make

%install
rm -rf ${RPM_BUILD_ROOT}
make install DESTDIR=${RPM_BUILD_ROOT}

%clean
rm -rf ${RPM_BUILD_ROOT}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)
%{_libdir}/libredblack.so.*

%files devel
%defattr(-, root, root)
%{_libdir}/lib*.so
%{_libdir}/*a
%{_prefix}/share/libredblack/*
%{_includedir}/*
%{_mandir}/man3/*
%{_mandir}/man1/*
%{_bindir}/*
%doc example.c
%doc example1.c
%doc example2.c
%doc example3.c
%doc example4.rb
