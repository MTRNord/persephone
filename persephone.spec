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
BuildRequires:  sed
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
# Sanitizers since they might be needed when building the debug version
BuildRequires:  libasan
BuildRequires:  libubsan
BuildRequires:  liblsan

Requires:       yaml-cpp
Requires:       uuid
Requires:       jsoncpp
Requires:       openssl
Requires:       ldns
Requires:       yaml-cpp
Requires:       icu

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
