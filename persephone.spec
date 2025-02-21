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
BuildRequires:  json-devel
BuildRequires:  uuid-devel
BuildRequires:  jsoncpp-devel
BuildRequires:  zlib-ng-devel
BuildRequires:  libssl-devel
BuildRequires:  ldns-devel
BuildRequires:  libevent-devel
BuildRequires:  yaml-cpp-devel
BuildRequires:  libicu-devel
BuildRequires:  libsodium-devel

Requires:       yaml-cpp
Requires:       uuid
Requires:       jsoncpp
Requires:       zlib-ng
Requires:       openssl
Requires:       ldns
Requires:       libevent
Requires:       yaml-cpp
Requires:       icu
Requires:       libsodium

%description
%{summary}.

%prep
%setup -q -n %{name}-%{version}

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
