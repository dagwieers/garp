%define name garp
%define version 0.7.2
%define release 1

Name: %{name}
Version: %{version}
Release: %{release}
Copyright: GPL
Group: Networking/Utilities
Url: http://mind.be/software/garp/
Source: http://mind.be/software/garp/%{name}-%{version}.tar.gz
Summary: Check unused IP addresses and automagically assign them.
Packager: Dag Wieers <dag@mind.be>

%description
Garp is a Gratuitous ARP implementation. Garp can be used to check
for unused IP addresses and automagically (and randomly) assign
unused IP addresses (from a given IP range).

%prep
%setup

%build
make

%install
make install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root)
%doc COPYING
%attr(755,root,root) /sbin/garp
/usr/man/man8/garp.8

%changelog 
* Sun Nov 21 1999 Dag Wieers <dag@mind.be>
- Upgraded to Garp 0.7.2
- Changed Url: and Source: to http://mind.be/software/garp/

* Fri Nov 19 1999 Dag Wieers <dag@mind.be>
- Upgraded to Garp 0.7.0

* Mon Nov 15 1999 Ulrik De Bie <ulrik@mind.be>
- Initial release
