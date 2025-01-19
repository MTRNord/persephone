Name:           persephone
Version:        0.0.0
Release:        1%{?dist}
Summary:        An experimental C++20 matrix server

License:        AGPL-3.0-or-later
URL:            https://github.com/MTRNord/persephone
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  clang
BuildRequires:  json-devel
BuildRequires:  c-ares-devel
BuildRequires:  yaml-cpp-devel

Requires:       c-ares
Requires:       yaml-cpp

%description
%{summary}.

%prep
%autosetup -c

%build
%cmake
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%{_bindir}/%{name}
