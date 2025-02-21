Name:           persephone
Version:        0.0.0
Release:        1%{?dist}
Summary:        An experimental C++23 matrix server

License:        AGPL-3.0-or-later
URL:            https://github.com/MTRNord/persephone
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  g++
BuildRequires:  git
BuildRequires:  json-devel
BuildRequires:  uuid-devel
BuildRequires:  jsoncpp-devel
BuildRequires:  zlib-devel
BuildRequires:  openssl-devel
BuildRequires:  ldns-devel
BuildRequires:  libevent-devel
BuildRequires:  yaml-cpp-devel
BuildRequires:  libicu-devel
BuildRequires:  libsodium-devel
BuildRequires:  libpq-devel

Requires:       yaml-cpp
Requires:       uuid
Requires:       jsoncpp
Requires:       zlib
Requires:       openssl
Requires:       ldns
Requires:       libevent
Requires:       yaml-cpp
Requires:       icu
Requires:       libsodium
Requires:       libpq

%description
%{summary}.

%prep
%setup -q -n %{name}-%{version}
# Fix ldns include path
sed -i 's%includedir=/usr/include/ldns/ldns%includedir=/usr/include/ldns%g' /usr/lib64/pkgconfig/ldns.pc

%build
%cmake .
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%{_bindir}/%{name}
%doc README.md
%license LICENSE

%changelog
%autochangelog
