Name:           persephone
Version:        0.0.0
Release:        1%{?dist}
Summary:        An experimental C++20 matrix server

License:        AGPL-3.0-or-later
URL:            https://github.com/MTRNord/persephone
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  meson
BuildRequires:  clang

%prep
%autosetup -c

%build
%meson
%meson_build

%install
%meson_install

%check
%meson_test

%files
%{_bindir}/%{name}
