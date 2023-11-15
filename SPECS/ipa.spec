# ipatests enabled by default, can be disabled with --without ipatests
%bcond_without ipatests
# default to not use XML-RPC in Rawhide, can be turned around with --with ipa_join_xml
# On RHEL 8 we should use --with ipa_join_xml
%bcond_with ipa_join_xml

# Linting is disabled by default, needed for upstream testing
%bcond_with lint

# Build documentation with sphinx
%bcond_with doc

# Build Python wheels
%bcond_with wheels

# 389-ds-base 1.4 no longer supports i686 platform, build only client
# packages, https://bugzilla.redhat.com/show_bug.cgi?id=1544386
%ifarch %{ix86}
    %{!?ONLY_CLIENT:%global ONLY_CLIENT 1}
%endif

# Define ONLY_CLIENT to only make the ipa-client and ipa-python
# subpackages
%{!?ONLY_CLIENT:%global ONLY_CLIENT 0}
%if %{ONLY_CLIENT}
    %global enable_server_option --disable-server
%else
    %global enable_server_option --enable-server
%endif

%if %{ONLY_CLIENT}
    %global with_ipatests 0
%endif

# Whether to build ipatests
%if %{with ipatests}
    %global with_ipatests_option --with-ipatests
%else
    %global with_ipatests_option --without-ipatests
%endif

# Whether to use XML-RPC with ipa-join
%if %{with ipa_join_xml}
    %global with_ipa_join_xml_option --with-ipa-join-xml
%else
    %global with_ipa_join_xml_option --without-ipa-join-xml
%endif

# lint is not executed during rpmbuild
# %%global with_lint 1
%if %{with lint}
    %global linter_options --enable-pylint --without-jslint --enable-rpmlint
%else
    %global linter_options --disable-pylint --without-jslint --disable-rpmlint
%endif

# Include SELinux subpackage
%if 0%{?fedora} >= 30 || 0%{?rhel} >= 8
    %global with_selinux 1
    %global selinuxtype targeted
    %global modulename ipa
%endif

%if 0%{?rhel}
%global package_name ipa
%global alt_name freeipa
%global krb5_version 1.18.2-26
%global krb5_kdb_version 8.0
# 0.7.16: https://github.com/drkjam/netaddr/issues/71
%global python_netaddr_version 0.7.19
%global samba_version 4.17.2-1
%global selinux_policy_version 3.14.3-52
%global slapi_nis_version 0.56.4
%global python_ldap_version 3.1.0-1
%if 0%{?rhel} < 9
# Bug 1929067 - PKI instance creation failed with new 389-ds-base build
%global ds_version 1.4.3.16-12
%else
%global ds_version 2.0.3-3
%endif

# Fix for TLS 1.3 PHA, RHBZ#1775158
%global httpd_version 2.4.37-21
%global bind_version 9.11.20-6

%else
# Fedora
%global package_name freeipa
%global alt_name ipa
# Fix for CVE-2020-28196
%global krb5_version 1.18.2-29
# 0.7.16: https://github.com/drkjam/netaddr/issues/71
%global python_netaddr_version 0.7.16

%global samba_version 2:4.17.2

# 3.14.5-45 or later includes a number of interfaces fixes for IPA interface
%global selinux_policy_version 3.14.5-45
%global slapi_nis_version 0.56.5

%global krb5_kdb_version 8.0

# fix for segfault in python3-ldap, https://pagure.io/freeipa/issue/7324
%global python_ldap_version 3.1.0-1

# Make sure to use 389-ds-base versions that fix https://github.com/389ds/389-ds-base/issues/4609
%if 0%{?fedora} < 34
%global ds_version %{lua: local v={}; v['32']='1.4.3.20-2'; v['33']='1.4.4.13-2'; print(v[rpm.expand('%{fedora}')])}
%else
%global ds_version 2.0.4-1
%endif

# Fix for TLS 1.3 PHA, RHBZ#1775146
%global httpd_version 2.4.41-9

%global bind_version 9.11.24-1
# Don't use Fedora's Python dependency generator on Fedora 30/rawhide yet.
# Some packages don't provide new dist aliases.
# https://docs.fedoraproject.org/en-US/packaging-guidelines/Python/
%{?python_disable_dependency_generator}
# Fedora
%endif

# BIND employs 'pkcs11' OpenSSL engine instead of native PKCS11
# Fedora 31+ uses OpenSSL engine, as well as Fedora ELN (RHEL9)
%if 0%{?fedora} || 0%{?rhel} >= 9
    %global openssl_pkcs11_version 0.4.10-6
    %global softhsm_version 2.5.0-4
%else
    %global with_bind_pkcs11 1
%endif

%if 0%{?rhel} == 8
# Make sure to use PKI versions that work with 389-ds fix for https://github.com/389ds/389-ds-base/issues/4609
%global pki_version 10.10.5
%else
# Make sure to use PKI versions that work with 389-ds fix for https://github.com/389ds/389-ds-base/issues/4609
%global pki_version 10.10.5
%endif

# RHEL 8.3+, F32+ has 0.79.13
%global certmonger_version 0.79.7-3

# RHEL 8.2+, F32+ has 3.58
%global nss_version 3.44.0-4

# RHEL 8.7+, F35+, adds IdP integration
%global sssd_version 2.7.0

%define krb5_base_version %(LC_ALL=C /usr/bin/pkgconf --modversion krb5 | grep -Eo '^[^.]+\.[^.]+' || echo %krb5_version)
%global kdcproxy_version 0.4-3

%if 0%{?fedora} >= 33 || 0%{?rhel} >= 9
# systemd with resolved enabled
# see https://pagure.io/freeipa/issue/8275
%global systemd_version 246.6-3
%else
%global systemd_version 239
%endif

# augeas support for new chrony options
# see https://pagure.io/freeipa/issue/8676
# Note: will need to be updated for RHEL9 when a fix is available for
# https://bugzilla.redhat.com/show_bug.cgi?id=1931787
%if 0%{?fedora} >= 33
%global augeas_version 1.12.0-6
%else
%global augeas_version 1.12.0-3
%endif

%global plugin_dir %{_libdir}/dirsrv/plugins
%global etc_systemd_dir %{_sysconfdir}/systemd/system
%global gettext_domain ipa

%define _hardened_build 1

# Work-around fact that RPM SPEC parser does not accept
# "Version: @VERSION@" in freeipa.spec.in used for Autoconf string replacement
%define IPA_VERSION 4.9.12
# Release candidate version -- uncomment with one percent for RC versions
#%%global rc_version %%nil
%define AT_SIGN @
# redefine IPA_VERSION only if its value matches the Autoconf placeholder
%if "%{IPA_VERSION}" == "%{AT_SIGN}VERSION%{AT_SIGN}"
    %define IPA_VERSION nonsense.to.please.RPM.SPEC.parser
%endif

%define NON_DEVELOPER_BUILD ("%{lua: print(rpm.expand('%{suffix:%IPA_VERSION}'):find('^dev'))}" == "nil")

Name:           %{package_name}
Version:        %{IPA_VERSION}
Release:        9%{?rc_version:.%rc_version}%{?dist}
Summary:        The Identity, Policy and Audit system

License:        GPLv3+
URL:            http://www.freeipa.org/
Source0:        https://releases.pagure.org/freeipa/freeipa-%{version}%{?rc_version}.tar.gz
# Only use detached signature for the distribution builds. If it is a developer build, skip it
%if %{NON_DEVELOPER_BUILD}
Source1:        https://releases.pagure.org/freeipa/freeipa-%{version}%{?rc_version}.tar.gz.asc
%endif

# RHEL spec file only: START: Change branding to IPA and Identity Management
# Moved branding logos and background to redhat-logos-ipa-80.4:
# header-logo.png, login-screen-background.jpg, login-screen-logo.png,
# product-name.png
# RHEL spec file only: END: Change branding to IPA and Identity Management

# RHEL spec file only: START
%if %{NON_DEVELOPER_BUILD}
%if 0%{?rhel} >= 8
Patch0001:      0001-user-or-group-name-explain-the-supported-format_rhbz#2150217.patch
Patch0002:      0002-Use-the-python-cryptography-parser-directly-in-cert-find_rhbz#2164349.patch
Patch0003:      0003-Upgrade-add-PKI-drop-in-file-if-missing_rhbz#2215336.patch
Patch0004:      0004-Upgrade-fix-replica-agreement_rhbz#2216551.patch
Patch0005:      0005-OTP-fix-data-type-to-avoid-endianness-issue_rhbz#2218293.patch
Patch0006:      0006-Backport-test-updates-8-9-release_rhbz#2218847.patch
Patch0007:      0007-ipa-kdb-fix-error-handling-of-is_master_host_rhbz#2214638.patch
Patch0008:      0008-ipatests-enable-firewall-rule-for-http-service-on-acme-client_rhbz#2230256.patch
Patch0009:      0009-User-plugin-improve-error-related-to-non-existing-idp_rhbz#2224572.patch
Patch0010:      0010-Prevent-admin-user-from-being-deleted_rhbz#1921181.patch
Patch0011:      0011-Fix-memory-leak-in-the-OTP-last-token-plugin_rhbz#2227783.patch
Patch0012:      0012-ipatests-fix-test_topology_rhbz#2232351.patch
Patch0013:      0013-Installer-activate-nss-and-pam-services-in-sssd.conf_rhbz#2216532.patch
Patch0014:      0014-ipa-kdb-Make-AD-SIGNEDPATH-optional-with-krb5-DAL-8.patch
Patch1001:      1001-Change-branding-to-IPA-and-Identity-Management.patch
Patch1002:      1002-Revert-freeipa.spec-depend-on-bind-dnssec-utils.patch
Patch1003:      1003-webui-IdP-Remove-arrow-notation-due-to-uglify-js-lim.patch
# Due to behavior changes in python3-dns 2.2.0, IPA overrides the setting of the
# nameserver property inherited from dns.resolver.Resolver class to allow the
# setting of nameservers with custom ports. The method used is only needed, and
# only works, on version 2.2.0, or later, of python3-dns. For RHEL 8, which uses
# series 1.xx, the method override is not needed to provide the same behavior.
Patch1004:      1004-Revert-DNSResolver-Fix-use-of-nameservers-with-ports.patch
%endif
%endif
# RHEL spec file only: END

# For the timestamp trick in patch application
BuildRequires:  diffstat

BuildRequires:  openldap-devel
# For KDB DAL version, make explicit dependency so that increase of version
# will cause the build to fail due to unsatisfied dependencies.
# DAL version change may cause code crash or memory leaks, it is better to fail early.
BuildRequires:  krb5-kdb-version = %{krb5_kdb_version}
BuildRequires:  krb5-kdb-devel-version = %{krb5_kdb_version}
BuildRequires:  krb5-devel >= %{krb5_version}
BuildRequires:  pkgconfig(krb5)
%if %{with ipa_join_xml}
# 1.27.4: xmlrpc_curl_xportparms.gssapi_delegation
BuildRequires:  xmlrpc-c-devel >= 1.27.4
%else
BuildRequires:  libcurl-devel
BuildRequires:  jansson-devel
%endif
BuildRequires:  popt-devel
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconfig
BuildRequires:  pkgconf
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  make
BuildRequires:  libtool
BuildRequires:  gettext
BuildRequires:  gettext-devel
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  systemd >= %{systemd_version}
# systemd-tmpfiles which is executed from make install requires apache user
BuildRequires:  httpd
BuildRequires:  nspr-devel
BuildRequires:  openssl-devel
BuildRequires:  libini_config-devel
BuildRequires:  cyrus-sasl-devel
%if ! %{ONLY_CLIENT}
BuildRequires:  389-ds-base-devel >= %{ds_version}
BuildRequires:  samba-devel >= %{samba_version}
BuildRequires:  libtalloc-devel
BuildRequires:  libtevent-devel
BuildRequires:  libuuid-devel
BuildRequires:  libpwquality-devel
BuildRequires:  libsss_idmap-devel
BuildRequires:  libsss_certmap-devel
BuildRequires:  libsss_nss_idmap-devel >= %{sssd_version}
BuildRequires:  nodejs(abi)
# use old dependency on RHEL 8 for now
%if 0%{?fedora} >= 31 || 0%{?rhel} >= 9
BuildRequires:  python3-rjsmin
%else
BuildRequires:  uglify-js
%endif
BuildRequires:  libverto-devel
BuildRequires:  libunistring-devel
# 0.13.0: https://bugzilla.redhat.com/show_bug.cgi?id=1584773
# 0.13.0-2: fix for missing dependency on python-six
BuildRequires:  python3-lesscpy >= 0.13.0-2
BuildRequires:  cracklib-dicts
# ONLY_CLIENT
%endif

#
# Build dependencies for makeapi/makeaci
#
BuildRequires:  python3-cffi
# RHEL 8 packages will not work with python3-dns 2.2.0 or newer.
BuildRequires:  python3-dns
BuildRequires:  python3-ldap >= %{python_ldap_version}
BuildRequires:  python3-libsss_nss_idmap
BuildRequires:  python3-netaddr >= %{python_netaddr_version}
BuildRequires:  python3-pyasn1
BuildRequires:  python3-pyasn1-modules
BuildRequires:  python3-six
BuildRequires:  python3-psutil

#
# Build dependencies for wheel packaging and PyPI upload
#
%if %{with wheels}
BuildRequires:  dbus-glib-devel
BuildRequires:  libffi-devel
BuildRequires:  python3-tox
%if 0%{?fedora} <= 28
BuildRequires:  python3-twine
%else
BuildRequires:  twine
%endif
BuildRequires:  python3-wheel
# with_wheels
%endif

%if %{with doc}
BuildRequires: python3-sphinx
BuildRequires: plantum1
BuildRequires: fontconfig
BuildRequires: google-noto-sans-vf-fonts
%endif

#
# Build dependencies for lint and fastcheck
#
%if %{with lint}
BuildRequires:  git
%if 0%{?fedora} < 34
# jsl is orphaned in Fedora 34+
BuildRequires:  jsl
%endif
BuildRequires:  nss-tools
BuildRequires:  rpmlint
BuildRequires:  softhsm

BuildRequires:  keyutils
BuildRequires:  python3-augeas
BuildRequires:  python3-cffi
BuildRequires:  python3-cryptography >= 1.6
BuildRequires:  python3-custodia >= 0.3.1
BuildRequires:  python3-dateutil
BuildRequires:  python3-dbus
# RHEL 8 packages will not work with python3-dns 2.2.0 or newer.
BuildRequires:  python3-dns >= 1.15
BuildRequires:  python3-docker
BuildRequires:  python3-gssapi >= 1.2.0
BuildRequires:  python3-jinja2
BuildRequires:  python3-jwcrypto >= 0.4.2
BuildRequires:  python3-ldap >= %{python_ldap_version}
BuildRequires:  python3-ldap >= %{python_ldap_version}
BuildRequires:  python3-lib389 >= %{ds_version}
BuildRequires:  python3-libipa_hbac
BuildRequires:  python3-libsss_nss_idmap
BuildRequires:  python3-lxml
BuildRequires:  python3-netaddr >= %{python_netaddr_version}
BuildRequires:  python3-netifaces
BuildRequires:  python3-paste
BuildRequires:  python3-pexpect
BuildRequires:  python3-pki >= %{pki_version}
BuildRequires:  python3-polib
BuildRequires:  python3-pyasn1
BuildRequires:  python3-pyasn1-modules
BuildRequires:  python3-pycodestyle
# .wheelconstraints.in limits pylint version in Azure and tox tests
BuildRequires:  python3-pylint
BuildRequires:  python3-pytest-multihost
BuildRequires:  python3-pytest-sourceorder
BuildRequires:  python3-qrcode-core >= 5.0.0
BuildRequires:  python3-samba
BuildRequires:  python3-six
BuildRequires:  python3-sss
BuildRequires:  python3-sss-murmur
BuildRequires:  python3-sssdconfig >= %{sssd_version}
BuildRequires:  python3-systemd
BuildRequires:  python3-yaml
BuildRequires:  python3-yubico
# with_lint
%endif

#
# Build dependencies for unit tests
#
%if ! %{ONLY_CLIENT}
BuildRequires:  libcmocka-devel
# Required by ipa_kdb_tests
BuildRequires:  krb5-server >= %{krb5_version}
# ONLY_CLIENT
%endif

# Build dependencies for SELinux policy
%if %{with selinux}
BuildRequires:  selinux-policy-devel >= %{selinux_policy_version}
%endif

%description
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).


%if ! %{ONLY_CLIENT}

%package server
Summary: The IPA authentication server
Requires: %{name}-server-common = %{version}-%{release}
Requires: %{name}-client = %{version}-%{release}
Requires: %{name}-common = %{version}-%{release}
Requires: python3-ipaserver = %{version}-%{release}
Requires: python3-ldap >= %{python_ldap_version}
Requires: 389-ds-base >= %{ds_version}
Requires: openldap-clients > 2.4.35-4
Requires: nss-tools >= %{nss_version}
Requires(post): krb5-server >= %{krb5_version}
Requires(post): krb5-server >= %{krb5_base_version}
Requires: krb5-kdb-version = %{krb5_kdb_version}
Requires: cyrus-sasl-gssapi%{?_isa}
Requires: chrony
Requires: httpd >= %{httpd_version}
Requires(preun): python3
Requires(postun): python3
Requires: python3-gssapi >= 1.2.0-5
Requires: python3-systemd
Requires: python3-mod_wsgi
Requires: mod_auth_gssapi >= 1.5.0
Requires: mod_ssl >= %{httpd_version}
Requires: mod_session >= %{httpd_version}
# 0.9.9: https://github.com/adelton/mod_lookup_identity/pull/3
Requires: mod_lookup_identity >= 0.9.9
Requires: acl
Requires: systemd-units >= %{systemd_version}
Requires(pre): systemd-units >= %{systemd_version}
Requires(post): systemd-units >= %{systemd_version}
Requires(preun): systemd-units >= %{systemd_version}
Requires(postun): systemd-units >= %{systemd_version}
Requires(pre): shadow-utils
Requires: selinux-policy >= %{selinux_policy_version}
Requires(post): selinux-policy-base >= %{selinux_policy_version}
Requires: slapi-nis >= %{slapi_nis_version}
Requires: pki-ca >= %{pki_version}
Requires: pki-kra >= %{pki_version}
# pki-acme package was split out in pki-10.10.0
Requires: (pki-acme >= %{pki_version} if pki-ca >= 10.10.0)
Requires: policycoreutils >= 2.1.12-5
Requires: tar
Requires(pre): certmonger >= %{certmonger_version}
Requires(pre): 389-ds-base >= %{ds_version}
Requires: fontawesome-fonts
Requires: open-sans-fonts
%if 0%{?fedora} >= 32 || 0%{?rhel} >= 9
# https://pagure.io/freeipa/issue/8632
Requires: openssl > 1.1.1i
%else
Requires: openssl
%endif
Requires: softhsm >= 2.0.0rc1-1
Requires: p11-kit
Requires: %{etc_systemd_dir}
Requires: gzip
Requires: oddjob
# 0.7.0-2: https://pagure.io/gssproxy/pull-request/172
Requires: gssproxy >= 0.7.0-2
Requires: sssd-dbus >= %{sssd_version}
Requires: libpwquality
Requires: cracklib-dicts
# NDR libraries are internal in Samba and change with version without changing SONAME
Requires: samba-client-libs >= %{samba_version}
# Due to RHBZ#2100916, libvert-libev is required by ipa-otp.
Requires: libverto-libev >= 0.3.2-1

Provides: %{alt_name}-server = %{version}
Conflicts: %{alt_name}-server
Obsoletes: %{alt_name}-server < %{version}

# With FreeIPA 3.3, package freeipa-server-selinux was obsoleted as the
# entire SELinux policy is stored in the system policy
Obsoletes: freeipa-server-selinux < 3.3.0

# upgrade path from monolithic -server to -server + -server-dns
Obsoletes: %{name}-server <= 4.2.0

# Versions of nss-pam-ldapd < 0.8.4 require a mapping from uniqueMember to
# member.
Conflicts: nss-pam-ldapd < 0.8.4

# RHEL spec file only: START: Do not build tests
%if 0%{?rhel} == 8
# ipa-tests subpackage was moved to separate srpm
Conflicts: ipa-tests < 3.3.3-9
%endif
# RHEL spec file only: END: Do not build tests

%description server
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If you are installing an IPA server, you need to install this package.


%package -n python3-ipaserver
Summary: Python libraries used by IPA server
BuildArch: noarch
%{?python_provide:%python_provide python3-ipaserver}
Requires: %{name}-server-common = %{version}-%{release}
Requires: %{name}-common = %{version}-%{release}
# we need pre-requires since earlier versions may break upgrade
Requires(pre): python3-ldap >= %{python_ldap_version}
Requires: python3-augeas
Requires: augeas-libs >= %{augeas_version}
Requires: python3-custodia >= 0.3.1
Requires: python3-dbus
# RHEL 8 packages will not work with python3-dns 2.2.0 or newer.
Requires: python3-dns >= 1.15
Requires: python3-gssapi >= 1.2.0
Requires: python3-ipaclient = %{version}-%{release}
Requires: python3-kdcproxy >= %{kdcproxy_version}
Requires: python3-lxml
Requires: python3-pki >= %{pki_version}
Requires: python3-pyasn1 >= 0.3.2-2
Requires: python3-sssdconfig >= %{sssd_version}
Requires: python3-psutil
Requires: rpm-libs
# Indirect dependency: use newer urllib3 with TLS 1.3 PHA support
%if 0%{?rhel}
Requires: python3-urllib3 >= 1.24.2-3
%else
Requires: python3-urllib3 >= 1.25.7
%endif

%description -n python3-ipaserver
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If you are installing an IPA server, you need to install this package.


%package server-common
Summary: Common files used by IPA server
BuildArch: noarch
Requires: %{name}-client-common = %{version}-%{release}
Requires: httpd >= %{httpd_version}
Requires: systemd-units >= %{systemd_version}
Requires: custodia >= 0.3.1
%if 0%{?rhel} >= 8 && ! 0%{?eln}
Requires: system-logos-ipa >= 80.4
%endif

Provides: %{alt_name}-server-common = %{version}
Conflicts: %{alt_name}-server-common
Obsoletes: %{alt_name}-server-common < %{version}

%description server-common
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If you are installing an IPA server, you need to install this package.


%package server-dns
Summary: IPA integrated DNS server with support for automatic DNSSEC signing
BuildArch: noarch
Requires: %{name}-server = %{version}-%{release}
Requires: bind-dyndb-ldap >= 11.2-2
Requires: bind >= %{bind_version}
Requires: bind-utils >= %{bind_version}
%if %{with bind_pkcs11}
Requires: bind-pkcs11 >= %{bind_version}
Requires: bind-pkcs11-utils >= %{bind_version}
%else
Requires: softhsm >= %{softhsm_version}
Requires: openssl-pkcs11 >= %{openssl_pkcs11_version}
%endif
# See https://bugzilla.redhat.com/show_bug.cgi?id=1825812
# RHEL 8.3+ and Fedora 32+ have 2.1
Requires: opendnssec >= 2.1.6-5
%{?systemd_requires}

Provides: %{alt_name}-server-dns = %{version}
Conflicts: %{alt_name}-server-dns
Obsoletes: %{alt_name}-server-dns < %{version}

# upgrade path from monolithic -server to -server + -server-dns
Obsoletes: %{name}-server <= 4.2.0

%description server-dns
IPA integrated DNS server with support for automatic DNSSEC signing.
Integrated DNS server is BIND 9. OpenDNSSEC provides key management.


%package server-trust-ad
Summary: Virtual package to install packages required for Active Directory trusts
Requires: %{name}-server = %{version}-%{release}
Requires: %{name}-common = %{version}-%{release}

Requires: samba >= %{samba_version}
Requires: samba-winbind
Requires: sssd-winbind-idmap
Requires: libsss_idmap
%if 0%{?rhel}
Obsoletes: ipa-idoverride-memberof-plugin <= 0.1
%endif
Requires(post): python3
Requires: python3-samba
Requires: python3-libsss_nss_idmap
Requires: python3-sss

# We use alternatives to divert winbind_krb5_locator.so plugin to libkrb5
# on the installes where server-trust-ad subpackage is installed because
# IPA AD trusts cannot be used at the same time with the locator plugin
# since Winbindd will be configured in a different mode
Requires(post): %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives
Requires(preun): %{_sbindir}/update-alternatives

Provides: %{alt_name}-server-trust-ad = %{version}
Conflicts: %{alt_name}-server-trust-ad
Obsoletes: %{alt_name}-server-trust-ad < %{version}

%description server-trust-ad
Cross-realm trusts with Active Directory in IPA require working Samba 4
installation. This package is provided for convenience to install all required
dependencies at once.

# ONLY_CLIENT
%endif


%package client
Summary: IPA authentication for use on clients
Requires: %{name}-client-common = %{version}-%{release}
Requires: %{name}-common = %{version}-%{release}
Requires: python3-gssapi >= 1.2.0-5
Requires: python3-ipaclient = %{version}-%{release}
Requires: python3-ldap >= %{python_ldap_version}
Requires: python3-sssdconfig >= %{sssd_version}
Requires: cyrus-sasl-gssapi%{?_isa}
Requires: chrony
Requires: krb5-workstation >= %{krb5_version}
# Support pkinit with client install
Requires: krb5-pkinit-openssl >= %{krb5_version}
# authselect: sssd profile with-subid
%if 0%{?fedora} >= 36
Requires: authselect >= 1.4.0
%else
Requires: authselect >= 1.2.5
%endif
Requires: curl
# NIS domain name config: /usr/lib/systemd/system/*-domainname.service
# All Fedora 28+ and RHEL8+ contain the service in hostname package
Requires: hostname
Requires: libcurl >= 7.21.7-2
%if %{with ipa_join_xml}
Requires: xmlrpc-c >= 1.27.4
%else
Requires: jansson
%endif
Requires: sssd-ipa >= %{sssd_version}
Requires: sssd-idp >= %{sssd_version}
Requires: sssd-krb5 >= %{sssd_version}
Requires: certmonger >= %{certmonger_version}
Requires: nss-tools >= %{nss_version}
Requires: bind-utils
Requires: oddjob-mkhomedir
Requires: libsss_autofs
Requires: autofs
Requires: libnfsidmap
Requires: nfs-utils
Requires: sssd-tools >= %{sssd_version}
Requires(post): policycoreutils

# https://pagure.io/freeipa/issue/8530
Recommends: libsss_sudo
Recommends: sudo
Requires: (libsss_sudo if sudo)

Provides: %{alt_name}-client = %{version}
Conflicts: %{alt_name}-client
Obsoletes: %{alt_name}-client < %{version}

Provides: %{alt_name}-admintools = %{version}
Conflicts: %{alt_name}-admintools
Obsoletes: %{alt_name}-admintools < 4.4.1

Obsoletes: %{name}-admintools < 4.4.1
Provides: %{name}-admintools = %{version}-%{release}

%if 0%{?rhel} == 8
# Conflict with crypto-policies < 20200629-1 to get AD-SUPPORT policy module
Conflicts: crypto-policies < 20200629-1
%endif

%description client
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If your network uses IPA for authentication, this package should be
installed on every client machine.
This package provides command-line tools for IPA administrators.

%package client-samba
Summary: Tools to configure Samba on IPA client
Group: System Environment/Base
Requires: %{name}-client = %{version}-%{release}
Requires: python3-samba
Requires: samba-client
Requires: samba-winbind
Requires: samba-common-tools
Requires: samba
Requires: sssd-winbind-idmap
Requires: tdb-tools
Requires: cifs-utils

%description client-samba
This package provides command-line tools to deploy Samba domain member
on the machine enrolled into a FreeIPA environment

%package client-epn
Summary: Tools to configure Expiring Password Notification in IPA
Group: System Environment/Base
Requires: %{name}-client = %{version}-%{release}
Requires: systemd-units >= %{systemd_version}
Requires(post): systemd-units >= %{systemd_version}
Requires(preun): systemd-units >= %{systemd_version}
Requires(postun): systemd-units >= %{systemd_version}

%description client-epn
This package provides a service to collect and send expiring password
notifications via email (SMTP).

%package -n python3-ipaclient
Summary: Python libraries used by IPA client
BuildArch: noarch
%{?python_provide:%python_provide python3-ipaclient}
Requires: %{name}-client-common = %{version}-%{release}
Requires: %{name}-common = %{version}-%{release}
Requires: python3-ipalib = %{version}-%{release}
Requires: python3-augeas
Requires: augeas-libs >= %{augeas_version}
# RHEL 8 packages will not work with python3-dns 2.2.0 or newer.
Requires: python3-dns >= 1.15
Requires: python3-jinja2

%description -n python3-ipaclient
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If your network uses IPA for authentication, this package should be
installed on every client machine.

%package client-common
Summary: Common files used by IPA client
BuildArch: noarch

Provides: %{alt_name}-client-common = %{version}
Conflicts: %{alt_name}-client-common
Obsoletes: %{alt_name}-client-common < %{version}
# python2-ipa* packages are no longer available in 4.8.
Obsoletes: python2-ipaclient < 4.8.0-1
Obsoletes: python2-ipalib < 4.8.0-1
Obsoletes: python2-ipaserver < 4.8.0-1
Obsoletes: python2-ipatests < 4.8.0-1


%description client-common
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If your network uses IPA for authentication, this package should be
installed on every client machine.


%package python-compat
Summary: Compatiblity package for Python libraries used by IPA
BuildArch: noarch
Obsoletes: %{name}-python < 4.2.91
Provides: %{name}-python = %{version}-%{release}
Requires: %{name}-common = %{version}-%{release}
Requires: python3-ipalib = %{version}-%{release}

Provides: %{alt_name}-python-compat = %{version}
Conflicts: %{alt_name}-python-compat
Obsoletes: %{alt_name}-python-compat < %{version}

Obsoletes: %{alt_name}-python < 4.2.91
Provides: %{alt_name}-python = %{version}

%description python-compat
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
This is a compatibility package to accommodate %{name}-python split into
python3-ipalib and %{name}-common. Packages still depending on
%{name}-python should be fixed to depend on python2-ipaclient or
%{name}-common instead.


%package -n python3-ipalib
Summary: Python3 libraries used by IPA
BuildArch: noarch
%{?python_provide:%python_provide python3-ipalib}
Provides: python3-ipapython = %{version}-%{release}
%{?python_provide:%python_provide python3-ipapython}
Provides: python3-ipaplatform = %{version}-%{release}
%{?python_provide:%python_provide python3-ipaplatform}
Requires: %{name}-common = %{version}-%{release}
# we need pre-requires since earlier versions may break upgrade
Requires(pre): python3-ldap >= %{python_ldap_version}
Requires: gnupg2
Requires: keyutils
Requires: python3-cffi
Requires: python3-cryptography >= 1.6
Requires: python3-dateutil
Requires: python3-dbus
# RHEL 8 packages will not work with python3-dns 2.2.0 or newer.
Requires: python3-dns >= 1.15
Requires: python3-gssapi >= 1.2.0
Requires: python3-jwcrypto >= 0.4.2
Requires: python3-libipa_hbac
Requires: python3-netaddr >= %{python_netaddr_version}
Requires: python3-netifaces >= 0.10.4
Requires: python3-pyasn1 >= 0.3.2-2
Requires: python3-pyasn1-modules >= 0.3.2-2
Requires: python3-pyusb
Requires: python3-qrcode-core >= 5.0.0
Requires: python3-requests
Requires: python3-six
Requires: python3-sss-murmur
Requires: python3-yubico >= 1.3.2-7
%if 0%{?rhel} && 0%{?rhel} == 8
Requires: platform-python-setuptools
%else
Requires: python3-setuptools
%endif

%description -n python3-ipalib
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If you are using IPA with Python 3, you need to install this package.


%package common
Summary: Common files used by IPA
BuildArch: noarch
Conflicts: %{name}-python < 4.2.91

Provides: %{alt_name}-common = %{version}
Conflicts: %{alt_name}-common
Obsoletes: %{alt_name}-common < %{version}

Conflicts: %{alt_name}-python < %{version}

%if %{with selinux}
# This ensures that the *-selinux package and all it’s dependencies are not
# pulled into containers and other systems that do not use SELinux. The
# policy defines types and file contexts for client and server.
Requires:       (%{name}-selinux if selinux-policy-%{selinuxtype})
%endif

%description common
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
If you are using IPA, you need to install this package.


%if %{with ipatests}

%package -n python3-ipatests
Summary: IPA tests and test tools
BuildArch: noarch
%{?python_provide:%python_provide python3-ipatests}
Requires: python3-ipaclient = %{version}-%{release}
Requires: python3-ipaserver = %{version}-%{release}
Requires: iptables
Requires: python3-coverage
Requires: python3-cryptography >= 1.6
Requires: python3-pexpect
%if 0%{?fedora}
# These packages do not exist on RHEL and for ipatests use
# they are installed on the controller through other means
Requires: ldns-utils
# update-crypto-policies
Requires: crypto-policies-scripts
Requires: python3-polib
Requires: python3-pytest >= 3.9.1
Requires: python3-pytest-multihost >= 0.5
Requires: python3-pytest-sourceorder
Requires: sshpass
%endif
Requires: python3-sssdconfig >= %{sssd_version}
Requires: tar
Requires: xz
Requires: openssh-clients
%if 0%{?rhel}
AutoReqProv: no
%endif

%description -n python3-ipatests
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).
This package contains tests that verify IPA functionality under Python 3.

# with ipatests
%endif


%if %{with selinux}
# SELinux subpackage
%package selinux
Summary:             FreeIPA SELinux policy
BuildArch:           noarch
Requires:            selinux-policy-%{selinuxtype}
Requires(post):      selinux-policy-%{selinuxtype}
%{?selinux_requires}

%description selinux
Custom SELinux policy module for FreeIPA
# with selinux
%endif


%prep
# Update timestamps on the files touched by a patch, to avoid non-equal
# .pyc/.pyo files across the multilib peers within a build, where "Level"
# is the patch prefix option (e.g. -p1)
# Taken from specfile for sssd and python-simplejson
UpdateTimestamps() {
  Level=$1
  PatchFile=$2

  # Locate the affected files:
  for f in $(diffstat $Level -l $PatchFile); do
    # Set the files to have the same timestamp as that of the patch:
    touch -c -r $PatchFile $f
  done
}

%setup -n freeipa-%{version}%{?rc_version} -q

# To allow proper application patches to the stripped po files, strip originals
pushd po
for i in *.po ; do
    msgattrib --translated --no-fuzzy --no-location -s $i > $i.tmp || exit 1
    mv $i.tmp $i || exit 1
done
popd

for p in %patches ; do
    %__patch -p1 -i $p
    UpdateTimestamps -p1 $p
done

%build
# PATH is workaround for https://bugzilla.redhat.com/show_bug.cgi?id=1005235
export PATH=/usr/bin:/usr/sbin:$PATH

export PYTHON=%{__python3}
autoreconf -ivf
%configure --with-vendor-suffix=-%{release} \
           %{enable_server_option} \
           %{with_ipatests_option} \
           %{with_ipa_join_xml_option} \
           %{linter_options}

# run build in default dir
# -Onone is workaround for https://bugzilla.redhat.com/show_bug.cgi?id=1398405
%make_build -Onone


%check
make %{?_smp_mflags} check VERBOSE=yes LIBDIR=%{_libdir}


%install
# Please put as much logic as possible into make install. It allows:
# - easier porting to other distributions
# - rapid devel & install cycle using make install
#   (instead of full RPM build and installation each time)
#
# All files and directories created by spec install should be marked as ghost.
# (These are typically configuration files created by IPA installer.)
# All other artifacts should be created by make install.

%make_install

# don't package ipasphinx for now
rm -rf %{buildroot}%{python3_sitelib}/ipasphinx*

%if %{with ipatests}
mv %{buildroot}%{_bindir}/ipa-run-tests %{buildroot}%{_bindir}/ipa-run-tests-%{python3_version}
mv %{buildroot}%{_bindir}/ipa-test-config %{buildroot}%{_bindir}/ipa-test-config-%{python3_version}
mv %{buildroot}%{_bindir}/ipa-test-task %{buildroot}%{_bindir}/ipa-test-task-%{python3_version}
ln -rs %{buildroot}%{_bindir}/ipa-run-tests-%{python3_version} %{buildroot}%{_bindir}/ipa-run-tests-3
ln -rs %{buildroot}%{_bindir}/ipa-test-config-%{python3_version} %{buildroot}%{_bindir}/ipa-test-config-3
ln -rs %{buildroot}%{_bindir}/ipa-test-task-%{python3_version} %{buildroot}%{_bindir}/ipa-test-task-3
ln -frs %{buildroot}%{_bindir}/ipa-run-tests-%{python3_version} %{buildroot}%{_bindir}/ipa-run-tests
ln -frs %{buildroot}%{_bindir}/ipa-test-config-%{python3_version} %{buildroot}%{_bindir}/ipa-test-config
ln -frs %{buildroot}%{_bindir}/ipa-test-task-%{python3_version} %{buildroot}%{_bindir}/ipa-test-task
# with_ipatests
%endif

# remove files which are useful only for make uninstall
find %{buildroot} -wholename '*/site-packages/*/install_files.txt' -exec rm {} \;

%if 0%{?rhel}
# RHEL spec file only: START
# Moved branding logos and background to redhat-logos-ipa-80.4:
# header-logo.png, login-screen-background.jpg, login-screen-logo.png,
# product-name.png
rm -f %{buildroot}%{_usr}/share/ipa/ui/images/header-logo.png
rm -f %{buildroot}%{_usr}/share/ipa/ui/images/login-screen-background.jpg
rm -f %{buildroot}%{_usr}/share/ipa/ui/images/login-screen-logo.png
rm -f %{buildroot}%{_usr}/share/ipa/ui/images/product-name.png
%endif
# RHEL spec file only: END

%find_lang %{gettext_domain}

%if ! %{ONLY_CLIENT}
# Remove .la files from libtool - we don't want to package
# these files
rm %{buildroot}/%{plugin_dir}/libipa_pwd_extop.la
rm %{buildroot}/%{plugin_dir}/libipa_enrollment_extop.la
rm %{buildroot}/%{plugin_dir}/libipa_winsync.la
rm %{buildroot}/%{plugin_dir}/libipa_repl_version.la
rm %{buildroot}/%{plugin_dir}/libipa_uuid.la
rm %{buildroot}/%{plugin_dir}/libipa_modrdn.la
rm %{buildroot}/%{plugin_dir}/libipa_lockout.la
rm %{buildroot}/%{plugin_dir}/libipa_cldap.la
rm %{buildroot}/%{plugin_dir}/libipa_dns.la
rm %{buildroot}/%{plugin_dir}/libipa_sidgen.la
rm %{buildroot}/%{plugin_dir}/libipa_sidgen_task.la
rm %{buildroot}/%{plugin_dir}/libipa_extdom_extop.la
rm %{buildroot}/%{plugin_dir}/libipa_range_check.la
rm %{buildroot}/%{plugin_dir}/libipa_otp_counter.la
rm %{buildroot}/%{plugin_dir}/libipa_otp_lasttoken.la
rm %{buildroot}/%{plugin_dir}/libipa_graceperiod.la
rm %{buildroot}/%{plugin_dir}/libtopology.la
rm %{buildroot}/%{_libdir}/krb5/plugins/kdb/ipadb.la
rm %{buildroot}/%{_libdir}/samba/pdb/ipasam.la

# So we can own our Apache configuration
mkdir -p %{buildroot}%{_sysconfdir}/httpd/conf.d/
/bin/touch %{buildroot}%{_sysconfdir}/httpd/conf.d/ipa.conf
/bin/touch %{buildroot}%{_sysconfdir}/httpd/conf.d/ipa-kdc-proxy.conf
/bin/touch %{buildroot}%{_sysconfdir}/httpd/conf.d/ipa-pki-proxy.conf
/bin/touch %{buildroot}%{_sysconfdir}/httpd/conf.d/ipa-rewrite.conf
/bin/touch %{buildroot}%{_usr}/share/ipa/html/ca.crt
/bin/touch %{buildroot}%{_usr}/share/ipa/html/krb.con
/bin/touch %{buildroot}%{_usr}/share/ipa/html/krb5.ini
/bin/touch %{buildroot}%{_usr}/share/ipa/html/krbrealm.con

mkdir -p %{buildroot}%{_libdir}/krb5/plugins/libkrb5
touch %{buildroot}%{_libdir}/krb5/plugins/libkrb5/winbind_krb5_locator.so

# ONLY_CLIENT
%endif

/bin/touch %{buildroot}%{_sysconfdir}/ipa/default.conf
/bin/touch %{buildroot}%{_sysconfdir}/ipa/ca.crt

%if ! %{ONLY_CLIENT}
mkdir -p %{buildroot}%{_sysconfdir}/cron.d
# ONLY_CLIENT
%endif

%if ! %{ONLY_CLIENT}

%post server
# NOTE: systemd specific section
    /bin/systemctl --system daemon-reload 2>&1 || :
# END
if [ $1 -gt 1 ] ; then
    /bin/systemctl condrestart certmonger.service 2>&1 || :
fi
/bin/systemctl reload-or-try-restart dbus
/bin/systemctl reload-or-try-restart oddjobd

%tmpfiles_create ipa.conf

%posttrans server
# don't execute upgrade and restart of IPA when server is not installed
%{__python3} -c "import sys; from ipalib import facts; sys.exit(0 if facts.is_ipa_configured() else 1);" > /dev/null 2>&1

if [  $? -eq 0 ]; then
    # This is necessary for Fedora system upgrades which by default
    # work with the network being offline
    /bin/systemctl start network-online.target

    # Restart IPA processes. This must be also run in postrans so that plugins
    # and software is in consistent state. This will also perform the
    # system upgrade.
    # NOTE: systemd specific section

    /bin/systemctl is-enabled ipa.service >/dev/null 2>&1
    if [  $? -eq 0 ]; then
        /bin/systemctl restart ipa.service >/dev/null
    fi

    /bin/systemctl is-enabled ipa-ccache-sweep.timer >/dev/null 2>&1
    if [  $? -eq 1 ]; then
        /bin/systemctl enable ipa-ccache-sweep.timer>/dev/null
    fi
fi
# END


%preun server
if [ $1 = 0 ]; then
# NOTE: systemd specific section
    /bin/systemctl --quiet stop ipa.service || :
    /bin/systemctl --quiet disable ipa.service || :
    /bin/systemctl reload-or-try-restart dbus
    /bin/systemctl reload-or-try-restart oddjobd
# END
fi


%pre server
# Stop ipa_kpasswd if it exists before upgrading so we don't have a
# zombie process when we're done.
if [ -e /usr/sbin/ipa_kpasswd ]; then
# NOTE: systemd specific section
    /bin/systemctl stop ipa_kpasswd.service >/dev/null 2>&1 || :
# END
fi


%pre server-common
# create users and groups
# create kdcproxy group and user
getent group kdcproxy >/dev/null || groupadd -f -r kdcproxy
getent passwd kdcproxy >/dev/null || useradd -r -g kdcproxy -s /sbin/nologin -d / -c "IPA KDC Proxy User" kdcproxy
# create ipaapi group and user
getent group ipaapi >/dev/null || groupadd -f -r ipaapi
getent passwd ipaapi >/dev/null || useradd -r -g ipaapi -s /sbin/nologin -d / -c "IPA Framework User" ipaapi
# add apache to ipaaapi group
id -Gn apache | grep '\bipaapi\b' >/dev/null || usermod apache -a -G ipaapi


%post server-dns
%systemd_post ipa-dnskeysyncd.service ipa-ods-exporter.socket ipa-ods-exporter.service

%preun server-dns
%systemd_preun ipa-dnskeysyncd.service ipa-ods-exporter.socket ipa-ods-exporter.service

%postun server-dns
%systemd_postun ipa-dnskeysyncd.service ipa-ods-exporter.socket ipa-ods-exporter.service


%postun server-trust-ad
if [ "$1" -ge "1" ]; then
    if [ "`readlink %{_sysconfdir}/alternatives/winbind_krb5_locator.so`" == "/dev/null" ]; then
        %{_sbindir}/alternatives --set winbind_krb5_locator.so /dev/null
    fi
fi


%post server-trust-ad
%{_sbindir}/update-alternatives --install %{_libdir}/krb5/plugins/libkrb5/winbind_krb5_locator.so \
        winbind_krb5_locator.so /dev/null 90
/bin/systemctl reload-or-try-restart dbus
/bin/systemctl reload-or-try-restart oddjobd


%posttrans server-trust-ad
%{__python3} -c "import sys; from ipalib import facts; sys.exit(0 if facts.is_ipa_configured() else 1);" > /dev/null 2>&1
if [  $? -eq 0 ]; then
# NOTE: systemd specific section
    /bin/systemctl try-restart httpd.service >/dev/null 2>&1 || :
# END
fi


%preun server-trust-ad
if [ $1 -eq 0 ]; then
    %{_sbindir}/update-alternatives --remove winbind_krb5_locator.so /dev/null
    /bin/systemctl reload-or-try-restart dbus
    /bin/systemctl reload-or-try-restart oddjobd
fi

# ONLY_CLIENT
%endif

%preun client-epn
%systemd_preun ipa-epn.service
%systemd_preun ipa-epn.timer

%postun client-epn
%systemd_postun ipa-epn.service
%systemd_postun ipa-epn.timer

%post client-epn
%systemd_post ipa-epn.service
%systemd_post ipa-epn.timer

%post client
if [ $1 -gt 1 ] ; then
    # Has the client been configured?
    restore=0
    test -f '/var/lib/ipa-client/sysrestore/sysrestore.index' && restore=$(wc -l '/var/lib/ipa-client/sysrestore/sysrestore.index' | awk '{print $1}')

    if [ -f '/etc/sssd/sssd.conf' -a $restore -ge 2 ]; then
        if grep -E -q '/var/lib/sss/pubconf/krb5.include.d/' /etc/krb5.conf  2>/dev/null ; then
            sed -i '\;includedir /var/lib/sss/pubconf/krb5.include.d;d' /etc/krb5.conf
        fi
    fi

    if [ $restore -ge 2 ]; then
        if grep -E -q '\s*pkinit_anchors = FILE:/etc/ipa/ca.crt$' /etc/krb5.conf 2>/dev/null; then
            sed -E 's|(\s*)pkinit_anchors = FILE:/etc/ipa/ca.crt$|\1pkinit_anchors = FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem\n\1pkinit_pool = FILE:/var/lib/ipa-client/pki/ca-bundle.pem|' /etc/krb5.conf >/etc/krb5.conf.ipanew
            mv -Z /etc/krb5.conf.ipanew /etc/krb5.conf
            cp /etc/ipa/ca.crt /var/lib/ipa-client/pki/kdc-ca-bundle.pem
            cp /etc/ipa/ca.crt /var/lib/ipa-client/pki/ca-bundle.pem
        fi

        %{__python3} -c 'from ipaclient.install.client import configure_krb5_snippet; configure_krb5_snippet()' >>/var/log/ipaupgrade.log 2>&1
        %{__python3} -c 'from ipaclient.install.client import update_ipa_nssdb; update_ipa_nssdb()' >>/var/log/ipaupgrade.log 2>&1
        chmod 0600 /var/log/ipaupgrade.log
        SSH_CLIENT_SYSTEM_CONF="/etc/ssh/ssh_config"
        if [ -f "$SSH_CLIENT_SYSTEM_CONF" ]; then
            sed -E --in-place=.orig 's/^(HostKeyAlgorithms ssh-rsa,ssh-dss)$/# disabled by ipa-client update\n# \1/' "$SSH_CLIENT_SYSTEM_CONF"
        fi
    fi
fi


%if %{with selinux}
# SELinux contexts are saved so that only affected files can be
# relabeled after the policy module installation
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
semodule -d ipa_custodia &> /dev/null || true;
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
    semodule -e ipa_custodia &> /dev/null || true;
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}
# with_selinux
%endif


%triggerin client -- openssh-server < 8.2
# Has the client been configured?
restore=0
test -f '/var/lib/ipa-client/sysrestore/sysrestore.index' && restore=$(wc -l '/var/lib/ipa-client/sysrestore/sysrestore.index' | awk '{print $1}')

if [ -f '/etc/ssh/sshd_config' -a $restore -ge 2 ]; then
    if grep -E -q '^(AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys|PubKeyAgent /usr/bin/sss_ssh_authorizedkeys %u)$' /etc/ssh/sshd_config 2>/dev/null; then
        sed -r '
            /^(AuthorizedKeysCommand(User|RunAs)|PubKeyAgentRunAs)[ \t]/ d
        ' /etc/ssh/sshd_config >/etc/ssh/sshd_config.ipanew

        if /usr/sbin/sshd -t -f /dev/null -o 'AuthorizedKeysCommand=/usr/bin/sss_ssh_authorizedkeys' -o 'AuthorizedKeysCommandUser=nobody' 2>/dev/null; then
            sed -ri '
                s/^PubKeyAgent (.+) %u$/AuthorizedKeysCommand \1/
                s/^AuthorizedKeysCommand .*$/\0\nAuthorizedKeysCommandUser nobody/
            ' /etc/ssh/sshd_config.ipanew
        elif /usr/sbin/sshd -t -f /dev/null -o 'AuthorizedKeysCommand=/usr/bin/sss_ssh_authorizedkeys' -o 'AuthorizedKeysCommandRunAs=nobody' 2>/dev/null; then
            sed -ri '
                s/^PubKeyAgent (.+) %u$/AuthorizedKeysCommand \1/
                s/^AuthorizedKeysCommand .*$/\0\nAuthorizedKeysCommandRunAs nobody/
            ' /etc/ssh/sshd_config.ipanew
        elif /usr/sbin/sshd -t -f /dev/null -o 'PubKeyAgent=/usr/bin/sss_ssh_authorizedkeys %u' -o 'PubKeyAgentRunAs=nobody' 2>/dev/null; then
            sed -ri '
                s/^AuthorizedKeysCommand (.+)$/PubKeyAgent \1 %u/
                s/^PubKeyAgent .*$/\0\nPubKeyAgentRunAs nobody/
            ' /etc/ssh/sshd_config.ipanew
        fi

        mv -Z /etc/ssh/sshd_config.ipanew /etc/ssh/sshd_config
        chmod 600 /etc/ssh/sshd_config

        /bin/systemctl condrestart sshd.service 2>&1 || :
    fi
fi


%triggerin client -- openssh-server >= 8.2
# Has the client been configured?
restore=0
test -f '/var/lib/ipa-client/sysrestore/sysrestore.index' && restore=$(wc -l '/var/lib/ipa-client/sysrestore/sysrestore.index' | awk '{print $1}')

if [ -f '/etc/ssh/sshd_config' -a $restore -ge 2 ]; then
    # If the snippet already exists, skip
    if [ ! -f '/etc/ssh/sshd_config.d/04-ipa.conf' ]; then
        # Take the values from /etc/ssh/sshd_config and put them in 04-ipa.conf
        grep -E '^(PubkeyAuthentication|KerberosAuthentication|GSSAPIAuthentication|UsePAM|ChallengeResponseAuthentication|AuthorizedKeysCommand|AuthorizedKeysCommandUser)' /etc/ssh/sshd_config 2>/dev/null > /etc/ssh/sshd_config.d/04-ipa.conf
        # Remove the values from sshd_conf
        sed -ri '
            /^(PubkeyAuthentication|KerberosAuthentication|GSSAPIAuthentication|UsePAM|ChallengeResponseAuthentication|AuthorizedKeysCommand|AuthorizedKeysCommandUser)[ \t]/ d
        ' /etc/ssh/sshd_config

        /bin/systemctl condrestart sshd.service 2>&1 || :
    fi
    # If the snippet has been created, ensure that it is included
    # either by /etc/ssh/sshd_config.d/*.conf or directly
    if [ -f '/etc/ssh/sshd_config.d/04-ipa.conf' ]; then
        if ! grep -E -q  '^\s*Include\s*/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config 2> /dev/null ; then
            if ! grep -E -q '^\s*Include\s*/etc/ssh/sshd_config.d/04-ipa\.conf' /etc/ssh/sshd_config 2> /dev/null ; then
                # Include the snippet
                echo "Include /etc/ssh/sshd_config.d/04-ipa.conf" > /etc/ssh/sshd_config.ipanew
                cat /etc/ssh/sshd_config >> /etc/ssh/sshd_config.ipanew
                mv -fZ --backup=existing --suffix .ipaold /etc/ssh/sshd_config.ipanew /etc/ssh/sshd_config
            fi
        fi
    fi
fi


%if ! %{ONLY_CLIENT}

%files server
%doc README.md Contributors.txt
%license COPYING
%{_sbindir}/ipa-backup
%{_sbindir}/ipa-restore
%{_sbindir}/ipa-ca-install
%{_sbindir}/ipa-kra-install
%{_sbindir}/ipa-server-install
%{_sbindir}/ipa-replica-conncheck
%{_sbindir}/ipa-replica-install
%{_sbindir}/ipa-replica-manage
%{_sbindir}/ipa-csreplica-manage
%{_sbindir}/ipa-server-certinstall
%{_sbindir}/ipa-server-upgrade
%{_sbindir}/ipa-ldap-updater
%{_sbindir}/ipa-otptoken-import
%{_sbindir}/ipa-compat-manage
%{_sbindir}/ipa-nis-manage
%{_sbindir}/ipa-managed-entries
%{_sbindir}/ipactl
%{_sbindir}/ipa-advise
%{_sbindir}/ipa-cacert-manage
%{_sbindir}/ipa-winsync-migrate
%{_sbindir}/ipa-pkinit-manage
%{_sbindir}/ipa-crlgen-manage
%{_sbindir}/ipa-cert-fix
%{_sbindir}/ipa-acme-manage
%{_libexecdir}/certmonger/dogtag-ipa-ca-renew-agent-submit
%{_libexecdir}/certmonger/ipa-server-guard
%dir %{_libexecdir}/ipa
%{_libexecdir}/ipa/ipa-ccache-sweeper
%{_libexecdir}/ipa/ipa-custodia
%{_libexecdir}/ipa/ipa-custodia-check
%{_libexecdir}/ipa/ipa-httpd-kdcproxy
%{_libexecdir}/ipa/ipa-httpd-pwdreader
%{_libexecdir}/ipa/ipa-pki-retrieve-key
%{_libexecdir}/ipa/ipa-pki-wait-running
%{_libexecdir}/ipa/ipa-otpd
%{_libexecdir}/ipa/ipa-print-pac
%{_libexecdir}/ipa/ipa-subids
%dir %{_libexecdir}/ipa/custodia
%attr(755,root,root) %{_libexecdir}/ipa/custodia/ipa-custodia-dmldap
%attr(755,root,root) %{_libexecdir}/ipa/custodia/ipa-custodia-pki-tomcat
%attr(755,root,root) %{_libexecdir}/ipa/custodia/ipa-custodia-pki-tomcat-wrapped
%attr(755,root,root) %{_libexecdir}/ipa/custodia/ipa-custodia-ra-agent
%dir %{_libexecdir}/ipa/oddjob
%attr(0755,root,root) %{_libexecdir}/ipa/oddjob/org.freeipa.server.conncheck
%attr(0755,root,root) %{_libexecdir}/ipa/oddjob/org.freeipa.server.config-enable-sid
%attr(0755,root,root) %{_libexecdir}/ipa/oddjob/org.freeipa.server.trust-enable-agent
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freeipa.server.conf
%config(noreplace) %{_sysconfdir}/oddjobd.conf.d/ipa-server.conf
%dir %{_libexecdir}/ipa/certmonger
%attr(755,root,root) %{_libexecdir}/ipa/certmonger/*
# NOTE: systemd specific section
%attr(644,root,root) %{_unitdir}/ipa.service
%attr(644,root,root) %{_unitdir}/ipa-otpd.socket
%attr(644,root,root) %{_unitdir}/ipa-otpd@.service
%attr(644,root,root) %{_unitdir}/ipa-ccache-sweep.service
%attr(644,root,root) %{_unitdir}/ipa-ccache-sweep.timer
# END
%attr(755,root,root) %{plugin_dir}/libipa_pwd_extop.so
%attr(755,root,root) %{plugin_dir}/libipa_enrollment_extop.so
%attr(755,root,root) %{plugin_dir}/libipa_winsync.so
%attr(755,root,root) %{plugin_dir}/libipa_repl_version.so
%attr(755,root,root) %{plugin_dir}/libipa_uuid.so
%attr(755,root,root) %{plugin_dir}/libipa_modrdn.so
%attr(755,root,root) %{plugin_dir}/libipa_lockout.so
%attr(755,root,root) %{plugin_dir}/libipa_dns.so
%attr(755,root,root) %{plugin_dir}/libipa_range_check.so
%attr(755,root,root) %{plugin_dir}/libipa_otp_counter.so
%attr(755,root,root) %{plugin_dir}/libipa_otp_lasttoken.so
%attr(755,root,root) %{plugin_dir}/libtopology.so
%attr(755,root,root) %{plugin_dir}/libipa_sidgen.so
%attr(755,root,root) %{plugin_dir}/libipa_sidgen_task.so
%attr(755,root,root) %{plugin_dir}/libipa_extdom_extop.so
%attr(755,root,root) %{plugin_dir}/libipa_graceperiod.so
%attr(755,root,root) %{_libdir}/krb5/plugins/kdb/ipadb.so
%{_mandir}/man1/ipa-replica-conncheck.1*
%{_mandir}/man1/ipa-replica-install.1*
%{_mandir}/man1/ipa-replica-manage.1*
%{_mandir}/man1/ipa-csreplica-manage.1*
%{_mandir}/man1/ipa-server-certinstall.1*
%{_mandir}/man1/ipa-server-install.1*
%{_mandir}/man1/ipa-server-upgrade.1*
%{_mandir}/man1/ipa-ca-install.1*
%{_mandir}/man1/ipa-kra-install.1*
%{_mandir}/man1/ipa-compat-manage.1*
%{_mandir}/man1/ipa-nis-manage.1*
%{_mandir}/man1/ipa-managed-entries.1*
%{_mandir}/man1/ipa-ldap-updater.1*
%{_mandir}/man8/ipactl.8*
%{_mandir}/man1/ipa-backup.1*
%{_mandir}/man1/ipa-restore.1*
%{_mandir}/man1/ipa-advise.1*
%{_mandir}/man1/ipa-otptoken-import.1*
%{_mandir}/man1/ipa-cacert-manage.1*
%{_mandir}/man1/ipa-winsync-migrate.1*
%{_mandir}/man1/ipa-pkinit-manage.1*
%{_mandir}/man1/ipa-crlgen-manage.1*
%{_mandir}/man1/ipa-cert-fix.1*
%{_mandir}/man1/ipa-acme-manage.1*


%files -n python3-ipaserver
%doc README.md Contributors.txt
%license COPYING
%{python3_sitelib}/ipaserver
%{python3_sitelib}/ipaserver-*.egg-info


%files server-common
%doc README.md Contributors.txt
%license COPYING
%ghost %verify(not owner group) %dir %{_sharedstatedir}/kdcproxy
%dir %attr(0755,root,root) %{_sysconfdir}/ipa/kdcproxy
%config(noreplace) %{_sysconfdir}/ipa/kdcproxy/kdcproxy.conf
# NOTE: systemd specific section
%{_tmpfilesdir}/ipa.conf
%attr(644,root,root) %{_unitdir}/ipa-custodia.service
%ghost %attr(644,root,root) %{etc_systemd_dir}/httpd.d/ipa.conf
# END
%{_usr}/share/ipa/wsgi.py*
%{_usr}/share/ipa/kdcproxy.wsgi
%{_usr}/share/ipa/ipaca*.ini
%{_usr}/share/ipa/*.ldif
%exclude %{_datadir}/ipa/ipa-cldap-conf.ldif
%{_usr}/share/ipa/*.uldif
%{_usr}/share/ipa/*.template
%dir %{_usr}/share/ipa/advise
%dir %{_usr}/share/ipa/advise/legacy
%{_usr}/share/ipa/advise/legacy/*.template
%dir %{_usr}/share/ipa/profiles
%{_usr}/share/ipa/profiles/README
%{_usr}/share/ipa/profiles/*.cfg
%dir %{_usr}/share/ipa/html
%{_usr}/share/ipa/html/ssbrowser.html
%{_usr}/share/ipa/html/unauthorized.html
%dir %{_usr}/share/ipa/migration
%{_usr}/share/ipa/migration/index.html
%{_usr}/share/ipa/migration/migration.py*
%dir %{_usr}/share/ipa/ui
%{_usr}/share/ipa/ui/index.html
%{_usr}/share/ipa/ui/reset_password.html
%{_usr}/share/ipa/ui/sync_otp.html
%{_usr}/share/ipa/ui/*.ico
%{_usr}/share/ipa/ui/*.css
%dir %{_usr}/share/ipa/ui/css
%{_usr}/share/ipa/ui/css/*.css
%dir %{_usr}/share/ipa/ui/js
%dir %{_usr}/share/ipa/ui/js/dojo
%{_usr}/share/ipa/ui/js/dojo/dojo.js
%dir %{_usr}/share/ipa/ui/js/libs
%{_usr}/share/ipa/ui/js/libs/*.js
%dir %{_usr}/share/ipa/ui/js/freeipa
%{_usr}/share/ipa/ui/js/freeipa/app.js
%{_usr}/share/ipa/ui/js/freeipa/core.js
%dir %{_usr}/share/ipa/ui/js/plugins
%dir %{_usr}/share/ipa/ui/images
%if 0%{?rhel}
%{_usr}/share/ipa/ui/images/facet-*.png
# Moved branding logos and background to redhat-logos-ipa-80.4:
# header-logo.png, login-screen-background.jpg, login-screen-logo.png,
# product-name.png
%else
%{_usr}/share/ipa/ui/images/*.jpg
%{_usr}/share/ipa/ui/images/*.png
%endif
%dir %{_usr}/share/ipa/wsgi
%{_usr}/share/ipa/wsgi/plugins.py*
%dir %{_sysconfdir}/ipa
%dir %{_sysconfdir}/ipa/html
%config(noreplace) %{_sysconfdir}/ipa/html/ssbrowser.html
%config(noreplace) %{_sysconfdir}/ipa/html/unauthorized.html
%ghost %attr(0644,root,root) %config(noreplace) %{_sysconfdir}/httpd/conf.d/ipa-rewrite.conf
%ghost %attr(0644,root,root) %config(noreplace) %{_sysconfdir}/httpd/conf.d/ipa.conf
%ghost %attr(0644,root,root) %config(noreplace) %{_sysconfdir}/httpd/conf.d/ipa-kdc-proxy.conf
%ghost %attr(0640,root,root) %config(noreplace) %{_sysconfdir}/httpd/conf.d/ipa-pki-proxy.conf
%ghost %attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipa/kdcproxy/ipa-kdc-proxy.conf
%ghost %attr(0644,root,root) %config(noreplace) %{_usr}/share/ipa/html/ca.crt
%ghost %attr(0640,root,named) %config(noreplace) %{_sysconfdir}/named/ipa-ext.conf
%ghost %attr(0640,root,named) %config(noreplace) %{_sysconfdir}/named/ipa-options-ext.conf
%ghost %attr(0644,root,root) %{_usr}/share/ipa/html/krb.con
%ghost %attr(0644,root,root) %{_usr}/share/ipa/html/krb5.ini
%ghost %attr(0644,root,root) %{_usr}/share/ipa/html/krbrealm.con
%dir %{_usr}/share/ipa/updates/
%{_usr}/share/ipa/updates/*
%dir %{_localstatedir}/lib/ipa
%attr(700,root,root) %dir %{_localstatedir}/lib/ipa/backup
%attr(700,root,root) %dir %{_localstatedir}/lib/ipa/gssproxy
%attr(711,root,root) %dir %{_localstatedir}/lib/ipa/sysrestore
%attr(700,root,root) %dir %{_localstatedir}/lib/ipa/sysupgrade
%attr(755,root,root) %dir %{_localstatedir}/lib/ipa/pki-ca
%attr(755,root,root) %dir %{_localstatedir}/lib/ipa/certs
%attr(700,root,root) %dir %{_localstatedir}/lib/ipa/private
%attr(700,root,root) %dir %{_localstatedir}/lib/ipa/passwds
%ghost %attr(775,root,pkiuser) %{_localstatedir}/lib/ipa/pki-ca/publish
%ghost %attr(770,named,named) %{_localstatedir}/named/dyndb-ldap/ipa
%dir %attr(0700,root,root) %{_sysconfdir}/ipa/custodia
%dir %{_usr}/share/ipa/schema.d
%attr(0644,root,root) %{_usr}/share/ipa/schema.d/README
%attr(0644,root,root) %{_usr}/share/ipa/gssapi.login
%{_usr}/share/ipa/ipakrb5.aug

%files server-dns
%doc README.md Contributors.txt
%license COPYING
%config(noreplace) %{_sysconfdir}/sysconfig/ipa-dnskeysyncd
%config(noreplace) %{_sysconfdir}/sysconfig/ipa-ods-exporter
%dir %attr(0755,root,root) %{_sysconfdir}/ipa/dnssec
%{_libexecdir}/ipa/ipa-dnskeysyncd
%{_libexecdir}/ipa/ipa-dnskeysync-replica
%{_libexecdir}/ipa/ipa-ods-exporter
%{_sbindir}/ipa-dns-install
%{_mandir}/man1/ipa-dns-install.1*
%attr(644,root,root) %{_unitdir}/ipa-dnskeysyncd.service
%attr(644,root,root) %{_unitdir}/ipa-ods-exporter.socket
%attr(644,root,root) %{_unitdir}/ipa-ods-exporter.service

%files server-trust-ad
%doc README.md Contributors.txt
%license COPYING
%{_sbindir}/ipa-adtrust-install
%{_usr}/share/ipa/smb.conf.empty
%attr(755,root,root) %{_libdir}/samba/pdb/ipasam.so
%attr(755,root,root) %{plugin_dir}/libipa_cldap.so
%{_datadir}/ipa/ipa-cldap-conf.ldif
%{_mandir}/man1/ipa-adtrust-install.1*
%ghost %{_libdir}/krb5/plugins/libkrb5/winbind_krb5_locator.so
%{_sysconfdir}/dbus-1/system.d/oddjob-ipa-trust.conf
%{_sysconfdir}/oddjobd.conf.d/oddjobd-ipa-trust.conf
%attr(755,root,root) %{_libexecdir}/ipa/oddjob/com.redhat.idm.trust-fetch-domains

# ONLY_CLIENT
%endif


%files client
%doc README.md Contributors.txt
%license COPYING
%{_sbindir}/ipa-client-install
%{_sbindir}/ipa-client-automount
%{_sbindir}/ipa-certupdate
%{_sbindir}/ipa-getkeytab
%{_sbindir}/ipa-rmkeytab
%{_sbindir}/ipa-join
%{_bindir}/ipa
%config %{_sysconfdir}/bash_completion.d
%config %{_sysconfdir}/sysconfig/certmonger
%{_mandir}/man1/ipa.1*
%{_mandir}/man1/ipa-getkeytab.1*
%{_mandir}/man1/ipa-rmkeytab.1*
%{_mandir}/man1/ipa-client-install.1*
%{_mandir}/man1/ipa-client-automount.1*
%{_mandir}/man1/ipa-certupdate.1*
%{_mandir}/man1/ipa-join.1*
%dir %{_libexecdir}/ipa/acme
%{_libexecdir}/ipa/acme/certbot-dns-ipa

%files client-samba
%doc README.md Contributors.txt
%license COPYING
%{_sbindir}/ipa-client-samba
%{_mandir}/man1/ipa-client-samba.1*


%files client-epn
%doc README.md Contributors.txt
%dir %{_sysconfdir}/ipa/epn
%license COPYING
%{_sbindir}/ipa-epn
%{_mandir}/man1/ipa-epn.1*
%{_mandir}/man5/epn.conf.5*
%attr(644,root,root) %{_unitdir}/ipa-epn.service
%attr(644,root,root) %{_unitdir}/ipa-epn.timer
%attr(600,root,root) %config(noreplace) %{_sysconfdir}/ipa/epn.conf
%attr(644,root,root) %config(noreplace) %{_sysconfdir}/ipa/epn/expire_msg.template


%files -n python3-ipaclient
%doc README.md Contributors.txt
%license COPYING
%dir %{python3_sitelib}/ipaclient
%{python3_sitelib}/ipaclient/*.py
%{python3_sitelib}/ipaclient/__pycache__/*.py*
%dir %{python3_sitelib}/ipaclient/install
%{python3_sitelib}/ipaclient/install/*.py
%{python3_sitelib}/ipaclient/install/__pycache__/*.py*
%dir %{python3_sitelib}/ipaclient/plugins
%{python3_sitelib}/ipaclient/plugins/*.py
%{python3_sitelib}/ipaclient/plugins/__pycache__/*.py*
%dir %{python3_sitelib}/ipaclient/remote_plugins
%{python3_sitelib}/ipaclient/remote_plugins/*.py
%{python3_sitelib}/ipaclient/remote_plugins/__pycache__/*.py*
%dir %{python3_sitelib}/ipaclient/remote_plugins/2_*
%{python3_sitelib}/ipaclient/remote_plugins/2_*/*.py
%{python3_sitelib}/ipaclient/remote_plugins/2_*/__pycache__/*.py*
%{python3_sitelib}/ipaclient-*.egg-info


%files client-common
%doc README.md Contributors.txt
%license COPYING
%dir %attr(0755,root,root) %{_sysconfdir}/ipa/
%ghost %attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipa/default.conf
%ghost %attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipa/ca.crt
%dir %attr(0755,root,root) %{_sysconfdir}/ipa/nssdb
# old dbm format
%ghost %attr(644,root,root) %config(noreplace) %{_sysconfdir}/ipa/nssdb/cert8.db
%ghost %attr(644,root,root) %config(noreplace) %{_sysconfdir}/ipa/nssdb/key3.db
%ghost %attr(644,root,root) %config(noreplace) %{_sysconfdir}/ipa/nssdb/secmod.db
# new sql format
%ghost %attr(644,root,root) %config(noreplace) %{_sysconfdir}/ipa/nssdb/cert9.db
%ghost %attr(644,root,root) %config(noreplace) %{_sysconfdir}/ipa/nssdb/key4.db
%ghost %attr(644,root,root) %config(noreplace) %{_sysconfdir}/ipa/nssdb/pkcs11.txt
%ghost %attr(600,root,root) %config(noreplace) %{_sysconfdir}/ipa/nssdb/pwdfile.txt
%ghost %attr(644,root,root) %config(noreplace) %{_sysconfdir}/pki/ca-trust/source/ipa.p11-kit
%dir %{_localstatedir}/lib/ipa-client
%dir %{_localstatedir}/lib/ipa-client/pki
%dir %{_localstatedir}/lib/ipa-client/sysrestore
%{_mandir}/man5/default.conf.5*
%dir %{_usr}/share/ipa/client
%{_usr}/share/ipa/client/*.template


%files python-compat
%doc README.md Contributors.txt
%license COPYING


%files common -f %{gettext_domain}.lang
%doc README.md Contributors.txt
%license COPYING
%dir %{_usr}/share/ipa
%dir %{_libexecdir}/ipa

%files -n python3-ipalib
%doc README.md Contributors.txt
%license COPYING

%{python3_sitelib}/ipapython/
%{python3_sitelib}/ipalib/
%{python3_sitelib}/ipaplatform/
%{python3_sitelib}/ipapython-*.egg-info
%{python3_sitelib}/ipalib-*.egg-info
%{python3_sitelib}/ipaplatform-*.egg-info


%if %{with ipatests}


%files -n python3-ipatests
%doc README.md Contributors.txt
%license COPYING
%{python3_sitelib}/ipatests
%{python3_sitelib}/ipatests-*.egg-info
%{_bindir}/ipa-run-tests-3
%{_bindir}/ipa-test-config-3
%{_bindir}/ipa-test-task-3
%{_bindir}/ipa-run-tests-%{python3_version}
%{_bindir}/ipa-test-config-%{python3_version}
%{_bindir}/ipa-test-task-%{python3_version}
%{_bindir}/ipa-run-tests
%{_bindir}/ipa-test-config
%{_bindir}/ipa-test-task
%{_mandir}/man1/ipa-run-tests.1*
%{_mandir}/man1/ipa-test-config.1*
%{_mandir}/man1/ipa-test-task.1*

# with ipatests
%endif


%if %{with selinux}
%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.*
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{modulename}
# with selinux
%endif

%changelog
* Wed Oct 04 2023 Julien Rische <jrische@redhat.com> - 4.9.12-9
- ipa-kdb: Make AD-SIGNEDPATH optional with krb5 DAL 8 and older
  Resolves: RHEL-12198

* Thu Aug 31 2023 Rafael Jeffman <rjeffman@redhat.com> - 4.9.12-8
- Require krb5 release 1.18.2-25 or later
  Resolves: RHBZ#2234711

* Wed Aug 16 2023 Rafael Jeffman <rjeffman@redhat.com> - 4.9.12-7
- ipatests: fix test_topology
  Resolves: RHBZ#2232351
- Installer: activate nss and pam services in sssd.conf
  Resolves: RHBZ#2216532

* Thu Aug 10 2023 Rafael Jeffman <rjeffman@redhat.com> - 4.9.12-6
- ipa-kdb: fix error handling of is_master_host()
  Resolves: RHBZ#2214638
- ipatests: enable firewall rule for http service on acme client
  Resolves: RHBZ#2230256
- User plugin: improve error related to non existing idp
  Resolves: RHBZ#2224572
- Prevent admin user from being deleted
  Resolves: RHBZ#1821181
- Fix memory leak in the OTP last token plugin
  Resolves: RHBZ#2227783

* Mon Jul 17 2023 Rafael Jeffman <rjeffman@redhat.com> - 4.9.12-5
- Upgrade: fix replica agreement, fix backported patch
  Related: RHBZ#2216551

* Fri Jun 30 2023 Rafael Jeffman <rjeffman@redhat.com> - 4.9.12-4
- kdb: Use-krb5_pac_full_sign_compat() when available
  Resolves: RHBZ#2176406
- OTP: fix-data-type-to-avoid-endianness-issue
  Resolves: RHBZ#2218293
- Upgrade: fix replica agreement
  Resolves: RHBZ#2216551
- Upgrade: add PKI drop-in file if missing
  Resolves: RHBZ#2215336
- Use the python-cryptography parser directly in cert-find
  Resolves: RHBZ#2164349
- Backport test updates
  Resolves: RHBZ#221884

* Wed Jun 21 2023 Julien Rische <jrische@redhat.com> - 4.9.12-3
- Rely on sssd-krb5 to include SSSD-generated krb5 configuration
  Resolves: RHBZ#2214563

* Thu May 25 2023 Rafael Jeffman <rjeffman@redhat.com> - 4.9.12-2
- Use the OpenSSL certificate parser in cert-find
  Resolves: RHBZ#2209947 

* Wed May 24 2023 Rafael Jeffman <rjeffman@redhat.com> - 4.9.12-1
- Rebase ipa to 4.9.12
  Resolves: RHBZ#2196425
- user or group name: explain the supported format
  Resolves: RHBZ#2150217

* Mon Dec 19 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.11-3
- Revert DNSResolver Fix use of nameservers with ports.
  Related: RHBZ#2141316

* Fri Dec 16 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.11-2
- webui IdP: Remove arrow notation due to uglify-js limitation
  Related: RHBZ#2141316

* Wed Dec 14 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.11-1
- Rebase ipa to 4.9.11
  Resolves: RHBZ#2141316
- updates: fix memberManager ACI to allow managers from a specified group
  Resolves: RHBZ#2056009
- Defer creating the final krb5.conf on clients
  Resolves: RHBZ#2148259
- Exclude installed policy module file from RPM verification
  Resolves: RHBZ#2149567
- Spec file: ipa-client depends on krb5-pkinit-openssl
  Resolves: RHBZ#2149889

* Thu Nov 24 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-8
- ipa man page format the EXAMPLES section
  Resolves: RHBZ#2129895
- Fix canonicalization issue in Web UI
  Resolves: RHBZ#2127035
- Remove idnssoaserial argument from dns zone API. 
  Resolves: RHBZ#2108630
- Warn for permissions with read/write/search/compare and no attrs
  Resolves: RHBZ#2098187
- Add PKINIT support to ipa-client-install
  Resolves: RHBZ#2075452
- Generate CNAMEs for TXT+URI location krb records
  Resolves: RHBZ#2104185
- Vault: fix interoperability issues with older RHEL systems
  Resolves: RHBZ#2144737
- Fix typo on ipaupgrade.log chmod during RPM %post snipppet
  Resolves: RHBZ#2140994

* Tue Nov 1 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-7
- Rebuild to samba 4.17.2.
  Related: RHBZ#2132051

* Mon Aug 22 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-6
- webui: Allow grace login limit
  Resolves: RHBZ#2109243
- check_repl_update: in progress is a boolean
  Resolves: RHBZ#2117303
- Disabling gracelimit does not prevent LDAP binds
  Resolves: RHBZ#2109236
- Set passwordgracelimit to match global policy on group pw policies
  Resolves: RHBZ#2115475

* Tue Jul 19 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-5
- webui: Do not allow empty pagination size
  Resolves: RHBZ#2094672

* Tue Jul 12 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-4
- Add end to end integration tests for external IdP
  Resolves: RHBZ#2106346

* Thu Jul 07 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-3
- Add explicit dependency for libvert-libev
  Resolves: RHBZ#2104929

* Fri Jul 01 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-2
- Preserve user: fix the confusing summary
  Resolves: RHBZ#2022028
- Only calculate LDAP password grace when the password is expired
  Related: RHBZ#782917

* Wed Jun 15 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.10-1
- Rebase to upstream release 4.9.10
  Remove upstream patches 0002 to 0016 that are part of version 4.9.10
  Remove patches 1101 that is part of version 4.9.10
  Rename patch 0001 to 1002 as it will be used in future RHEL 8 releases
  Add patches 0001 and 0002 to fix build on RHEL 8.7
  Resolves: RHBZ#2079466
  Resolves: RHBZ#2063155
  Resolves: RHBZ#1958777
  Resolves: RHBZ#2068088
  Resolves: RHBZ#2004646
  Resolves: RHBZ#782917
  Resolves: RHBZ#2059396
  Resolves: RHBZ#2092015

* Tue Apr 5 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-8
- Backport latest test fixes in python3-ipatests
  Resolves: RHBZ#2060841
- extdom: user getorigby{user|group}name if available
  Resolves: RHBZ#2062379
- Set the mode on ipaupgrade.log during RPM post snipppet
  Resolves: RHBZ#2061957
- test_krbtpolicy: skip SPAKE-related tests in FIPS mode
  Resolves: RHBZ#1909630

* Thu Feb 24 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-7
- ipatests: Backport test fixes in python3-ipatests.
  Resolves: RHBZ#2057505

* Mon Feb 14 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-6
- ipatests: fix TestOTPToken::test_check_otpd_after_idle_timeout
  Related: RHBZ#2053024

* Mon Feb 14 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-5
- ipatests: remove additional check for failed units.
  Resolves: RHBZ#2053024
- ipa-cldap: fix memory leak.
  Resolves: RHBZ#2032738

* Thu Feb 10 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-4
- Don't always override the port in import_included_profiles
  Fixes: RHBZ#2022483
- Remove ipa-join errors from behind the debug option
  Fixes: RHBZ#2048558
- Enable the ccache sweep timer during installation
  Fixes: RHBZ#2051575

* Thu Feb 3 2022 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-3
- Config plugin: return EmptyModlist when no change is applied.
  Resolves: RHBZ#2031825
- Custodia: use a stronger encryption algo when exporting keys.
  Resolves: RHBZ#2032806
- ipa-kdb: do not remove keys for hardened auth-enabled users.
  Resolves: RHBZ#2033342
- ipa-pki-proxy.conf: provide access to /kra/admin/kra/getStatus
  Resolves: RHBZ#2049167
- Backport latest test fxes in python3 ipatests.
  Resolves: RHBZ#2048509
- Removed unused patch files that were part of 4.9.8 rebase.

* Fri Dec 10 2021 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-2
- Revert bind-pkcs11-utils configuration in freeipa.spec.
  Resolves: RHBZ#2026732

* Tue Nov 30 2021 Rafael Jeffman <rjeffman@redhat.com> - 4.9.8-1
- Upstream release FreeIPA 4.9.8
  Related: RHBZ#2015607
- Hardening for CVE-2020-25717

* Fri Nov 12 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.6-9.1
- Fix S4U2Self regression for cross-realm requester SID buffer
- Related: RHBZ#2021443

* Fri Nov 12 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.6-9
- Require samba 4.14.5-13 with IPA DC server role fixes
- Related: RHBZ#2021443

* Fri Nov 12 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.6-8
- Add versioned dependency of samba-client-libs to ipa-server
- Related: RHBZ#2021443

* Thu Nov 11 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.6-7
- Hardening for CVE-2020-25717
- Harden processing of trusted domains' users in S4U operations
- Resolves: RHBZ#2021443

* Wed Nov 10 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.6-6
- Hardening for CVE-2020-25717
- Rebuild against samba-4.14.5-11.el8
- Resolves: RHBZ#2021443

* Sun Nov 07 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.6-5
- Hardening for CVE-2020-25717
- Related: RHBZ#2019668

* Thu Jul 22 2021 Thomas Woerner <twoerner@redhat.com> - 4.9.6-4
- ipatests: NAMED_CRYPTO_POLICY_FILE not defined for RHEL
  Resolves: RHBZ#1982956

* Thu Jul 15 2021 Thomas Woerner <twoerner@redhat.com> - 4.9.6-3
- man page: update ipa-server-upgrade.1
  Resolves: RHBZ#1973273
- Fall back to krbprincipalname when validating host auth indicators
  Resolves: RHBZ#1979625
- Add dependency for sssd-winbind-idmap to server-trust-ad
  Resolves: RHBZ#1982211

* Thu Jul  8 2021 Thomas Woerner <twoerner@redhat.com> - 4.9.6-2
- IPA server in debug mode fails to run because time.perf_counter_ns is
  Python 3.7+
  Resolves: RHBZ#1974822
- Add checks to prevent assigning authentication indicators to internal IPA
  services
  Resolves: RHBZ#1979625
- Unable to set ipaUserAuthType with stageuser-add
  Resolves: RHBZ#1979605

* Thu Jul  1 2021 Thomas Woerner <twoerner@redhat.com> - 4.9.6-1
- Upstream release FreeIPA 4.9.6
  Related: RHBZ#1945038
- Revise PKINIT upgrade code
  Resolves: RHBZ#1886837
- ipa-cert-fix man page: add note about certmonger renewal
  Resolves: RHBZ#1780317
- Certificate Serial Number issue
  Resolves: RHBZ#1919384

* Mon Jun 14 2021 Thomas Woerner <twoerner@redhat.com> - 4.9.5-1
- Upstream release FreeIPA 4.9.5
  Related: RHBZ#1945038
- IPA to allow setting a new range type
  Resolves: RHBZ#1688267
- ipa-server-install displays debug output when --debug output is not
  specified.
  Resolves: RHBZ#1943151
- ACME fails to generate a cert on migrated RHEL8.4 server
  Resolves: RHBZ#1934991
- Switch ipa-client to use the JSON API
  Resolves: RHBZ#1937856
- IDM - Allow specifying permanent logging settings for BIND
  Resolves: RHBZ#1951511
- Cache LDAP data within a request
  Resolves: RHBZ#1953656
- ipa-server-upgrade is failing while upgrading rhel8.3 to rhel8.4
  Resolves: RHBZ#1957768

* Wed Mar 31 2021 Thomas Woerner <twoerner@redhat.com> - 4.9.3-1
- Upstream release FreeIPA 4.9.3
  Resolves: RHBZ#1945038

* Mon Feb 15 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.2-1
- Upstream release FreeIPA 4.9.2
  Related: RHBZ#1891832

* Wed Jan 27 2021 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.1-1
- Upstream release FreeIPA 4.9.1
  Related: RHBZ#1891832

* Mon Jan  4 2021 Thomas Woerner <twoerner@redhat.com> - 4.9.0-1
- Upstream final release FreeIPA 4.9.0
  Related: RHBZ#1891832

* Fri Dec 11 2020 Thomas Woerner <twoerner@redhat.com> - 4.9.0-0.5.rc3
- Upstream pre release FreeIPA 4.9.0rc3
  Related: RHBZ#1891832

* Fri Dec  4 2020 Alexander Bokovoy <abokovoy@redhat.com> - 4.9.0-0.3.rc2
- Remove ipa-server dependency from ipa-selinux subpackage
- Related: RHBZ#1891832

* Fri Dec  4 2020 Thomas Woerner <twoerner@redhat.com> - 4.9.0-0.2.rc2
- Upstream pre release FreeIPA 4.9.0rc2
  Related: RHBZ#1891832
- Synchronize spec file with upstream and Fedora
  Related: RHBZ#1891832
- Traceback while doing ipa-backup
  Resolves: RHBZ#1901068
- ipa-client-install changes system wide ssh configuration
  Resolves: RRBZ#1544379
- ipa-kdb: support subordinate/superior UPN suffixes
  Resolves: RHBZ#1891056
- KRA Transport and Storage Certificates do not renew
  Resolves: RHBZ#1872603
- Move where the restore state is marked during IPA server upgrade
  Resolves: RHBZ#1569011
- Intermittent IdM Client Registration Failures
  Resolves: RHBZ#1812871
- Nightly test failure in test_acme.py::TestACME::test_third_party_certs
  (updates-testing)
  Resolves: RHBZ#1903025
- Add IPA RA Agent to ACME group on the CA
  Resolves: RHBZ#1902727

* Mon Nov 23 2020 Thomas Woerner <twoerner@redhat.com> - 4.9.0-0.1.rc1
- Fix requirement for python3-kdcproxy, add no autoreqprov for ipatests sub
  package
  Related: RHBZ#1891832

* Mon Nov 23 2020 Thomas Woerner <twoerner@redhat.com> - 4.9.0-0.rc1
- Upstream pre release FreeIPA 4.9.0rc1
  Resolves: RHBZ#1891832
- Requirements and design for libpwquality integration
  Resolves: RHBZ#1340463
- When parsing options require name/value pairs
  Resolves: RHBZ#1357495
- WebUI: Fix issue with opening links in new tab/window
  Resolves: RHBZ#1484088
- Use a state to determine if a 389-ds upgrade is in progress
  Resolves: RHBZ#1569011
- Unlock user accounts after a password reset and replicate that unlock to
  all IdM servers
  Resolves: RHBZ#1784657
- Set the certmonger subject with a string, not an object
  Resolves: RHBZ#1810148
- Implement ACME certificate enrolment
  Resolves: RHBZ#1851835
- [WebUI] Backport jQuery patches from newer versions of the library (e.g.
  3.5.0)
  Resolves: RHBZ#1859249
- It is not possible to edit KDC database when the FreeIPA server is running
  Resolves: RHBZ#1875001
- Fix nsslapd-db-lock tuning of BDB backend
  Resolves: RHBZ#1882340
- ipa-kdb: support subordinate/superior UPN suffixes
  Resolves: RHBZ#1891056
- wgi/plugins.py: ignore empty plugin directories
  Resolves: RHBZ#1894800

* Thu Sep 10 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-11
- SELinux Policy: let custodia replicate keys
  Resolves: RHBZ#1868432

* Wed Aug 19 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-10
- Set mode of /etc/ipa/ca.crt to 0644 in CA-less installations
  Resolves: RHBZ#1870202

* Mon Aug 17 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-9
- CAless installation: set the perms on KDC cert file
  Resolves: RHBZ#1863616
- EPN: handle empty attributes
  Resolves: RHBZ#1866938
- IPA-EPN: enhance input validation
  Resolves: RHBZ#1866291
- EPN: enhance input validation
  Resolves: RHBZ#1863079
- Require new samba build 4.12.3-52
  Related: RHBZ#1868558
- Require new selinux-policy build 3.14.3-52
  Related: RHBZ#1869311

* Fri Jul 31 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-8
- [WebUI] IPA Error 3007: RequirmentError" while adding members in
  "User ID overrides" tab (updated)
  Resolves: RHBZ#1757045
- ipa-client-install: use the authselect backup during uninstall
  Resolves: RHBZ#1810179
- Replace SSLCertVerificationError with CertificateError for py36
  Resolves: RHBZ#1858318
- Fix AVC denial during ipa-adtrust-install --add-agents
  Resolves: RHBZ#1859213

* Wed Jul 15 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-7
- replica install failing with avc denial for custodia component
  Resolves: RHBZ#1857157

* Tue Jul 14 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-6
- selinux don't audit rules deny fetching trust topology
  Resolves: RHBZ#1845596
- fix iPAddress cert issuance for >1 host/service
  Resolves: RHBZ#1846352
- Specify cert_paths when calling PKIConnection
  Resolves: RHBZ#1849155
- Update crypto policy to allow AD-SUPPORT when installing IPA
  Resolves: RHBZ#1851139
- Add version to ipa-idoverride-memberof obsoletes
  Related: RHBZ#1846434

* Thu Jul 02 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-5
- Add missing ipa-selinux package
  Resolves: RHBZ#1853263

* Mon Jun 29 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-4
- Remove client-epn left over files for ONLY_CLIENT
  Related: RHBZ#1847999

* Mon Jun 29 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-3
- [WebUI] IPA Error 3007: RequirmentError" while adding members in
  "User ID overrides" tab
  Resolves: RHBZ#1757045
- EPN does not ship its default configuration ( /etc/ipa/epn.conf ) in
  freeipa-client-epn
  Resolves: RHBZ#1847999
- FreeIPA - Utilize 256-bit AJP connector passwords
  Resolves: RHBZ#1849914
- ipa: typo issue in ipanthomedirectoryrive deffinition
  Resolves: RHBZ#1851411

* Thu Jun 11 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-2
- Remove ipa-idoverride-memberof as superceded by ipa-server 4.8.7
  Resolves: RHBZ#1846434

* Thu Jun 11 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.7-1
- Upstream release FreeIPA 4.8.7
- Require new samba build 4.12.3-0
  Related: RHBZ#1818765
- New client-epn sub package
  Resolves: RHBZ#913799

* Tue Jun 02 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.6-2
- Support krb5 1.18
  Resolves: RHBZ#1817579

* Tue Apr 28 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.6-1
- Upstream release FreeIPA 4.8.6
- New SELinux sub package to provide own module
- Depend on selinux-policy-devel 3.14.3-43 for build due to a makefile issue in
  SELinux external policy support
  Related: RHBZ#1818765

* Mon Feb 17 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.4-6
- Allow an empty cookie in dogtag-ipa-ca-renew-agent-submit
  Resolves: RHBZ#1790663

* Mon Feb 17 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.4-5
- Fixed weekday in 4.8.4-2 changelog date
  Related: RHBZ#1784003
- adtrust: print DNS records for external DNS case after role is enabled
  Resolves: RHBZ#1665051
- AD user without override receive InternalServerError with API
  Resolves: RHBZ#1782572
- ipa-client-automount fails after repeated installation/uninstallation
  Resolves: RHBZ#1790886
- install/updates: move external members past schema compat update
  Resolves: RHBZ#1803165
- kdb: make sure audit_as_req callback signature change is preserved
  Resolves: RHBZ#1803786

* Wed Jan 29 2020 Thomas Woerner <twoerner@redhat.com> - 4.8.4-4
- Update dependencies for samba, 389-ds and sssd
  Resolves: RHBZ#1792848

* Fri Jan 17 2020 Alexander Bokovoy <abokovoy@redhat.com> - 4.8.4-3
- Depend on krb5-kdb-version-devel for BuildRequires
- Update nss dependency to 3.44.0-4
- Reset per-indicator Kebreros policy
  Resolves: RHBZ#1784761

* Sat Dec 14 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.4-2
- DNS install check: Fix overlapping DNS zone from the master itself
  Resolves: RHBZ#1784003

* Sat Dec 14 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.4-1
- Rebase to upstream release 4.8.4
  - Removed upstream patches 0001 to 0008 that are part of version 4.8.3-3
  Resolves: RHBZ#1782658
  Resolves: RHBZ#1782169
  Resolves: RHBZ#1783046
  Related: RHBZ#1748987

* Mon Dec  2 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.3-3
- Fix otptoken_sync plugin
  Resolves: RHBZ#1777811

* Mon Dec  2 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.3-2
- Use default crypto policy for TLS and enable TLS 1.3 support
  Resolves: RHBZ#1777809
- Covscan fixes
  Resolves: RHBZ#1777920
- Change pki_version to 10.8.0
  Related: RHBZ#1748987

* Thu Nov 28 2019 Alexander Bokovoy <abokovoy@redhat.com> - 4.8.3-1
- Rebase to security release 4.8.3 (CVE-2019-14867, CVE-2019-10195)
  Resolves: RHBZ#1767304
  Resolves: RHBZ#1776939
- Support KDC ticket policies for authentication indicators
  Resolves: RHBZ#1777564

* Tue Nov 26 2019 Alexander Bokovoy <abokovoy@redhat.com> - 4.8.2-4
- CVE-2019-14867: Denial of service in IPA server due to wrong use of ber_scanf()
  Resolves: RHBZ#1767304
- CVE-2019-10195: Don't log passwords embedded in commands in calls using batch
  Resolves: RHBZ#1776939

* Fri Nov 22 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.2-3
- Use default ssh host key algorithms
  Resolves: RHBZ#1756432
- Do not run trust upgrade code if master lacks Samba bindings
  Resolves: RHBZ#1757064
- Finish group membership management UI
  Resolves: RHBZ#1773528

* Mon Nov 18 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.2-2
- Update dependency for bind-dndb-ldap to 11.2-2
  Related: RHBZ#1762813

* Thu Nov 14 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.2-1
- Rebase to upstream release 4.8.2
  - Removed upstream patches 0001 to 0010 that are part of version 4.8.2
  - Updated branding patch
  Resolves: RHBZ#1748987

* Thu Aug 29 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-10
- Fix automount behavior with authselect
  Resolves: RHBZ#1740167

* Mon Aug 19 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-9
- extdom: unify error code handling especially LDAP_NO_SUCH_OBJECT
  Resolves: RHBZ#1741530

* Thu Aug 15 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-8
- FreeIPA 4.8.0 tarball lacks two update files that are in git
  Resolves: RHBZ#1741170

* Tue Aug 13 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-7
- Allow insecure binds for migration
  Resolves: RHBZ#1731963

* Fri Aug  2 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-6
- Fix --external-ca-profile not passed to CSR
  Resolves: RHBZ#1731813

* Tue Jul 30 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-5
- Remove posixAccount from service_find search filter
  Resolves: RHBZ#1731437
- Fix repeated uninstallation of ipa-client-samba crashes
  Resolves: RHBZ#1732529
- WebUI: Add PKINIT status field to 'Configuration' page
  Resolves: RHBZ#1518153

* Tue Jul 16 2019 Alexander Bokovoy <abokovoy@redhat.com> - 4.8.0-4
- Fix krb5-kdb-server -> krb5-kdb-version
  Related: RHBZ#1700121

* Mon Jul 15 2019 Alexander Bokovoy <abokovoy@redhat.com> - 4.8.0-3
- Make sure ipa-server depends on krb5-kdb-version to pick up
  right MIT Kerberos KDB ABI
  Related: RHBZ#1700121
- User field separator uses '$$' within ipaSELInuxUserMapOrder
  Fixes: RHBZ#1729099

* Wed Jul  3 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-2
- Fixed kdcproxy_version to 0.4-3
- Fixed krb5_version to 1.17-7
  Related: RHBZ#1684528

* Wed Jul  3 2019 Thomas Woerner <twoerner@redhat.com> - 4.8.0-1
- New upstream release 4.8.0
  - New subpackage: freeipa-client-samba
  - Added command ipa-cert-fix with man page
  - New sysconfdir sysconfig/certmonger
- Updated pki_version, certmonger_version, sssd_version and kdcproxy_version
  Related: RHBZ#1684528

* Tue May 21 2019 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.90-3
- Fix upgrade issue with AD trust when no trust yet established
  Fixes: RHBZ#1708874
  Related: RHBZ#1684528

* Thu May  9 2019 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.90-2
- Require certmonger 0.79.7-1
  Related: RHBZ#1708095

* Mon May  6 2019 Thomas Woerner <twoerner@redhat.com> - 4.7.90-1
- Update to 4.7.90-pre1
  Related: RHBZ#1684528
- Removed patches 0002 to 0031 as these are upsteram and part of 4.7.90-pre1
- Added new patches 0001-revert-minssf-defaults.patch and
  0001-Correct-default-fontawesome-path-broken-by-da2cf1c5.patch

* Tue Apr 16 2019 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.1-12
- Remove strict dependencies to krb5-server version in order to allow
  update of krb5 to 1.17 and change dependency to KDB DAL version.
  Resolves: RHBZ#1700121

* Wed Feb 27 2019 Rob Crittenden <rcritten@redhat.com> - 4.7.1-11
- Handle NFS configuration file changes. nfs-utils moved the
  configuration file from /etc/sysconfig/nfs to /etc/nfs.conf.
  Resolves: RHBZ#1676981

* Tue Jan 15 2019 Christian Heimes <cheimes@redhat.com> - 4.7.1-10
- Fix systemd-user HBAC rule
  Resolves: RHBZ#1664974

* Mon Jan 14 2019 Thomas Woerner <twoerner@redhat.com> - 4.7.1-9
- Resolve user/group names in idoverride*-find
  Resolves: RHBZ#1657745

* Mon Jan 14 2019 Christian Heimes <cheimes@redhat.com> - 4.7.1-8
- Create systemd-user HBAC service and rule
  Resolves: RHBZ#1664974
- ipaserver/dcerpc: fix exclusion entry with a forest trust domain info returned
  Resolves: RHBZ#1664023

* Fri Dec 14 2018 Thomas Woerner <twoerner@redhat.com> - 4.7.1-7.el8
- Fix misleading errors during client install rollback
  Resolves: RHBZ#1658283
- ipa-advise: update url of cacerdir_rehash tool
  Resolves: RHBZ#1658287
- Handle NTP configuration in a replica server installation
  Resolves: RHBZ#1651679
- Fix defects found by static analysis
  Resolves: RHBZ#1658182
- ipa-replica-install --setup-adtrust: check for package ipa-server-trust-ad
  Resolves: RHBZ#1658294
- ipaldap: invalid modlist when attribute encoding can vary
  Resolves: RHBZ#1658302
- Allow ipaapi and Apache user to access SSSD IFP
  Resolves: RHBZ#1639910
- Add sysadm_r to default SELinux user map order
  Resolves: RHBZ#1658303
- certdb: ensure non-empty Subject Key Identifier and validate server cert sig
  Resolves: RHBZ#1641988
- ipa-replica-install: password and admin-password options mutually exclusive
  Resolves: RHBZ#1658309
- ipa upgrade: handle double-encoded certificates
  Resolves: RHBZ#1658310
- PKINIT: fix ipa-pkinit-manage enable|disable
  Resolves: RHBZ#1658313
- Enable LDAP debug output in client to display TLS errors in join
  Resolves: RHBZ#1658316
- rpc: always read response
  Resolves: RHBZ#1639890
- ipa vault-retrieve: fix internal error
  Resolves: RHBZ#1658485
- Move ipa's systemd tmpfiles from /var/run to /run
  Resolves: RHBZ#1658487
- Fix authselect invocations to work with 1.0.2
  Resolves: RHBZ#1654291
- ipa-client-automount and NFS unit name changes
  Resolves: RHBZ#1645501
- Fix compile issue with new 389-ds
  Resolves: RHBZ#1659448

* Thu Nov 15 2018 Lumír Balhar <lbalhar@redhat.com> - 4.7.1-6.el8
- Require platform-python-setuptools instead of python3-setuptools
- Resolves: rhbz#1650139

* Mon Oct 29 2018 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.1-5.el8
- Fixed: rhbz#1643445 - External CA step 2 fails with pki_client_database_dir is missing
- Fixed: rhbz#1642834 - Smart card advise script uses hard-coded Python interpreter

* Tue Oct 16 2018 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.1-4.el8
- Fix mapping of BUILTIN\Guests to 'nobody' group during upgrade
  to not use generated Samba config at this point
- Related: rhbz#1623895

* Mon Oct 15 2018 Thomas Woerner <twoerner@redhat.com> - 4.7.1-3.el8
- New command automember-find-orphans to find and remove orphan automemeber
  rules has been added
  Resolves: RHBZ#1638373
- Moved ipa/idm logos and background to redhat-logos-ipa-80.4:
  header-logo.png, login-screen-background.jpg, login-screen-logo.png,
  product-name.png
  New requirement to redhat-logos-ipa >= 80.4 in ipa-server-common
  Resolves: RHBZ#1626507

* Wed Oct 10 2018 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.1-2.el8
- Move initialization of Guests mapping after cifs/ principal is created
- Related: rhbz#1623895

* Sun Oct 07 2018 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.1-1.el8
- 4.7.1
- Fixes: rhbz#1633105 - rebase to 4.7.1

* Tue Sep 25 2018 Tomas Orsava <torsava@redhat.com> - 4.7.0-6.el8
- Require the Python interpreter directly instead of using the package name
- Related: rhbz#1619153

* Thu Sep 13 2018 Rob Crittenden <rcritten@redhat.com> - 4.7.0-5.el8
- sudo rule for "admins" members should be created by default (#1609873)

* Thu Sep  6 2018 Rob Crittenden <rcritten@redhat.com> - 4.7.0-4.el8
- ipaclient-install: chmod needs octal permissions (#1609880)

* Thu Aug 16 2018 Thomas Woerner <twoerner@redhat.com> - 4.7.0-3.1.el8
- Resolves: #1609883 ipaserver/plugins/cert.py: Add reason to raise of
  errors.NotFound
- Resolves: #1615765 do-not-use-RC4-in-FIPS-mode
  - Move fips_enabled to a common library to share across different plugins
  - ipasam: do not use RC4 in FIPS mode

* Mon Aug 13 2018 Thomas Woerner <twoerner@redhat.com> - 4.7.0-3.el8
- Resolves: #1614301 Remove --no-sssd and --noac options
- Resolves: #1613879 Disable Domain Level 0
  - New patch sets to disable domain level 0
  - New adapted patch to disable DL0 specific tests (pytest_ipa vs.
    pytest_plugins)
  - Adapted branding patch in ipa-replica-install.1 due to DL0 removal

* Wed Jul 25 2018 Alexander Bokovoy <abokovoy@redhat.com> - 4.7.0-2.el8
- Require 389-ds-base-legacy-tools for setup tools

* Thu Jul 19 2018 Rob Crittenden <rcritten@redhat.com> - 4.7.0-1.el8
- Update to upstream 4.7.0 GA

* Mon May 21 2018 Rob Crittenden <rcritten@redhat.com> - 4.6.90.pre1-2.el8
- Set krb5 DAL version to 7.0 (#1580711)
- Rebuild aclocal and configure during build

* Mon Mar 26 2018 Rob Crittenden <rcritten@redhat.com> - 4.6.90.pre1-1.el8
- Update to upstream 4.6.90.pre1

* Mon Jan 29 2018 Troy Dawson <tdawson@redhat.com> - 4.5.4-5.el8.1
- Use java-1.8.0-openjdk-devel

* Thu Nov 30 2017 Alexander Bokovoy <abokovoy@redhat.com> - 4.5.4-5.el7
- Resolves: #1415162 ipa-exdom-extop plugin can exhaust DS worker threads

* Fri Nov 3 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.4-4.el7
- Resolves: #1388135 [RFE] limit the retro changelog to dns subtree.
  - ldap: limit the retro changelog to dns subtree
- Resolves: #1427798 Use X509v3 Basic Constraints "CA:TRUE" instead
  of "CA:FALSE" IPA CA CSR
  - Include the CA basic constraint in CSRs when renewing a CA
- Resolves: #1493145 ipa-replica-install might fail because of an already
  existing entry cn=ipa-http-delegation,cn=s4u2proxy,cn=etc,$SUFFIX
  - Checks if replica-s4u2proxy.ldif should be applied
- Resolves: #1493150 [RFE] set nsslapd-ignore-time-skew: on by default
  - ds: ignore time skew during initial replication step
  - ipa-replica-manage: implicitly ignore initial time skew in force-sync
- Resolves: #1500218 Replica installation at domain-level 0 fails against
  upgraded ipa-server
  - Fix ipa-replica-conncheck when called with --principal
- Resolves: #1506188 server-del doesn't remove dns-server configuration
  from ldap

* Thu Oct 26 2017 Rob Crittenden <rcritten@redhat.com> - 4.5.4-3.el7
- Drop workaround for building on AArch64 (#1482244)
- Temporarily reduce Requires on python-netaddr to 0.7.5-7 (#1506485)

* Tue Oct 24 2017 Felipe Barreto <fbarreto@redhat.com> - 4.5.4-2.el7
- Resolves: #1461177 ipa-otptoken-import  - XML file is missing PBKDF2
  parameters!
- Resolves: #1464205 NULL LDAP context in call to ldap_search_ext_s during
  search in cn=ad, cn=trusts,dc=example,dc=com
- Resolves: #1467887 iommu platform support for ipxe
- Resolves: #1477178 [ipa-replica-install] - 406 Client Error: Failed to
  validate message: Incorrect number of results (0) searching forpublic key for
  host
- Resolves: #1478251 IPA WebUI does not work after upgrade from IPA 4.4 to
  4.5
- Resolves: #1480102 ipa-server-upgrade failes with "This entry already
  exists"
- Resolves: #1482802 Unable to set ca renewal master on replica
- Resolves: #1484428 Updating from RHEL 7.3 fails with Server-Cert not found
  (ipa-server-upgrade)
- Resolves: #1484826 FreeIPA/IdM installations which were upgraded from
  versions with 389 DS prior to 1.3.3.0 doesn't have whomai plugin enabled and
  thus startup of Web UI fails
- Resolves: #1486283 TypeError in renew_ca_cert prevents from swiching back
  to self-signed CA
- Resolves: #1469246 Replica install fails to configure IPA-specific
  temporary files/directories
- Resolves: #1469480 bind package is not automatically updated during
  ipa-server upgrade process
- Resolves: #1475238 Use CommonNameToSANDefault in default profile (new
  installs only)
- Resolves: #1477703 IPA upgrade fails for latest ipa package

* Fri Oct 20 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.4-1.el7
- Use OpenJDK 8 to bootstrap on AArch64 until RH1482244 is resolved in
  buildroot
- Resolves: #1470177 - Rebase IPA to latest 4.5.x version
- Resolves: #1398594 ipa topologysuffix-verify should only warn about
  maximum number of replication agreements.
- Resolves: #1404236 Web UI: Change "Host Based" and "Role Based"
  to "Host-Based" and "Role-Based"
- Resolves: #1409786 Second phase of --external-ca ipa-server-install
  setup fails when dirsrv is not running
- Resolves: #1451576 ipa cert-request failed to generate certificate from csr
- Resolves: #1452086 Pagination Size under Customization in IPA WebUI
  accepts negative values
- Resolves: #1458169 --force-join option is not mentioned in
  ipa-replica-install man page
- Resolves: #1463186 IPA shouldn't allow objectclass if not all in lower case
- Resolves: #1478322 user-show command fails when sizelimit is configured
  to number <= number of entity which is user member of
- Resolves: #1496775 Enterprise principals should be able to trigger
  a refresh of the trusted domain data in the KDC
- Resolves: #1502533 Changing cert-find to go through the proxy
  instead of using the port 8080
- Resolves: #1502663 pkinit-status command fails after an upgrade from
  a pre-4.5 IPA
- Resolves: #1498168 Error when trying to modify a PTR record
- Resolves: #1457876 ipa-backup fails silently
- Resolves: #1493531 In case full PKINIT configuration is failing during
  server/replica install the error message should be more meaningful.
- Resolves: #1449985 Suggest CA installation command in KRA installation
  warning

* Wed Sep 20 2017 Felipe Barreto <fbarreto@redhat.com> - 4.5.0-21.el7.2.2
- Resolves: #1477367 ipa-server-upgrade timeouts on wait_for_open ports
  expecting IPA services listening on IPv6 ports
    - Make sure upgrade also checks for IPv6 stack
    - control logging of host_port_open from caller
    - log progress of wait_for_open_ports
- Resolves: #1477243 ipa help command returns traceback when no cache
  is present
    - Store help in Schema before writing to disk
    - Disable pylint in get_help function because of type confusion.

* Tue Sep 19 2017 Felipe Barreto <fbarreto@redhat.com> - 4.5.0-21.el7.2
- Resolves: #1477178 - [ipa-replica-install] - 406 Client Error: Failed to
  validate message: Incorrect number of results (0) searching forpublic
  key for host
    - Always check peer has keys before connecting
- Resolves: #1482802 - Unable to set ca renewal master on replica
    - Fix ipa config-mod --ca-renewal-master
- Resolves: #1486283 - TypeError in renew_ca_cert prevents from swiching
  back to self-signed CA
    - Backport PR 988 to ipa-4-5 Fix Certificate renewal (with ext ca)
- Resolves: #1480102 - ipa-server-upgrade failes with "This entry already exists"
    - Backport PR 1008 to ipa-4-5 Fix ipa-server-upgrade: This entry already exists
- Resolves: #1484826 - FreeIPA/IdM installations which were upgraded from
  versions with 389 DS prior to 1.3.3.0 doesn't have whomai plugin enabled and
  thus startup of Web UI fails
    - Adds whoami DS plugin in case that plugin is missing
- Resolves: #1478251 - IPA WebUI does not work after upgrade from IPA 4.4 to 4.5
    - Fixing how sssd.conf is updated when promoting a client to replica
- Resolves: #1461177 - ipa-otptoken-import - XML file is missing PBKDF2
  parameters!
    - ipa-otptoken-import: Make PBKDF2 refer to the pkcs5 namespace
- Resolves: #1484428 - Updating from RHEL 7.3 fails with Server-Cert not found
  (ipa-server-upgrade)
    - Backport 4-5: Fix ipa-server-upgrade with server cert tracking

* Thu Aug 17 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-21.el7.1.2
- Resolves: #1477703 IPA upgrade fails for latest ipa package
    - Restore old version of caIPAserviceCert for upgrade only

* Tue Aug 15 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-21.el7.1.1
- Resolves: #1475238 Use CommonNameToSANDefault in default profile
  (new installs only)
  - Restore old version of caIPAserviceCert for upgrade only

* Fri Jul 28 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-21.el7.1
- Resolves: #1455946 Provide a tooling automating the configuration
  of Smart Card authentication on a FreeIPA master
  - smart-card advises: configure systemwide NSS DB also on master
  - smart-card advises: add steps to store smart card signing CA cert
  - Allow to pass in multiple CA cert paths to the smart card advises
  - add a class that tracks the indentation in the generated advises
  - delegate the indentation handling in advises to dedicated class
  - advise: add an infrastructure for formatting Bash compound statements
  - delegate formatting of compound Bash statements to dedicated classes
  - Fix indentation of statements in Smart card advises
  - Use the compound statement formatting API for configuring PKINIT
  - smart card advises: use a wrapper around Bash `for` loops
  - smart card advise: use password when changing trust flags on HTTP cert
  - smart-card-advises: ensure that krb5-pkinit is installed on client
- Resolves: #1475238 Use CommonNameToSANDefault in default profile
  (new installs only)
  - Add CommonNameToSANDefault to default cert profile
- Resolves: #1464205 NULL LDAP context in call to ldap_search_ext_s
  during search in cn=ad,cn=trusts,dc=example,dc=com
  - NULL LDAP context in call to ldap_search_ext_s during search

* Wed Jul 12 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-21.el7
- Resolves: #1469246 Replica install fails to configure IPA-specific
  temporary files/directories
  - replica install: drop-in IPA specific config to tmpfiles.d
- Resolves: #1469480 bind package is not automatically updated during
  ipa-server upgrade process
  - Bumped Required version of bind-dyndb-ldap and bind package

* Tue Jun 27 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-20.el7
- Resolves: #1452216 Replica installation grants HTTP principal
  access in WebUI
  - Make sure we check ccaches in all rpcserver paths

* Wed Jun 21 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-19.el7
- Resolves: #1462112 ipaserver installation fails in FIPS mode: OpenSSL
  internal error, assertion failed: Digest MD4 forbidden in FIPS mode!
  - ipa-sam: replace encode_nt_key() with E_md4hash()
  - ipa_pwd_extop: do not generate NT hashes in FIPS mode
- Resolves: #1377973 ipa-server-install fails when the provided or resolved
  IP address is not found on local interfaces
  - Fix local IP address validation
  - ipa-dns-install: remove check for local ip address
  - refactor CheckedIPAddress class
  - CheckedIPAddress: remove match_local param
  - Remove ip_netmask from option parser
  - replica install: add missing check for non-local IP address
  - Remove network and broadcast address warnings

* Thu Jun 15 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-18.el7
- Resolves: #1449189 ipa-kra-install timeouts on replica
  - kra: promote: Get ticket before calling custodia

* Wed Jun 14 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-17.el7
- Resolve: #1455946 Provide a tooling automating the configuration
  of Smart Card authentication on a FreeIPA master
  - server certinstall: update KDC master entry
  - pkinit manage: introduce ipa-pkinit-manage
  - server upgrade: do not enable PKINIT by default
  - Extend the advice printing code by some useful abstractions
  - Prepare advise plugin for smart card auth configuration
- Resolve: #1461053 allow to modify list of UPNs of a trusted forest
  - trust-mod: allow modifying list of UPNs of a trusted forest
  - WebUI: add support for changing trust UPN suffixes

* Wed Jun 7 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-16.el7
- Resolves: #1377973 ipa-server-install fails when the provided or resolved
  IP address is not found on local interfaces
  - Only warn when specified server IP addresses don't match intf
- Resolves: #1438016 gssapi errors after IPA server upgrade
  - Bump version of python-gssapi
- Resolves: #1457942 certauth: use canonical principal for lookups
  - ipa-kdb: use canonical principal in certauth plugin
- Resolves: #1459153 Do not send Max-Age in ipa_session cookie to avoid
  breaking older clients
  - Add code to be able to set default kinit lifetime
  - Revert setting sessionMaxAge for old clients

* Wed Jun 7 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-15.el7
- Resolves: #1442233 IPA client commands fail when pointing to replica
  - httpinstance: wait until the service entry is replicated
- Resolves: #1456769 ipaAnchorUUID index incorrectly configured and then
  not indexed
  - Fix index definition for ipaAnchorUUID
- Resolves: #1438016 gssapi errors after IPA server upgrade
  - Avoid possible endless recursion in RPC call
  - rpc: preparations for recursion fix
  - rpc: avoid possible recursion in create_connection
- Resolves: #1446087 services entries missing krbCanonicalName attribute.
  - Changing cert-find to do not use only primary key to search in LDAP.
- Resolves: #1452763 ipa certmaprule change not reflected in krb5kdc workers
  - ipa-kdb: reload certificate mapping rules periodically
- Resolves: #1455541 after upgrade login from web ui breaks
  - kdc.key should not be visible to all
- Resolves: #1435606 Add pkinit_indicator option to KDC configuration
  - ipa-kdb: add pkinit authentication indicator in case of a successful
    certauth
- Resolves: #1455945 Enabling OCSP checks in mod_nss breaks certificate
  issuance when ipa-ca records are not resolvable
  - Turn off OCSP check
- Resolves: #1454483 rhel73 ipa ui - cannot del server - IPA Error 903 -
  server_del - TypeError: 'NoneType' object is not iterable
  - fix incorrect suffix handling in topology checks

* Wed May 24 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-14.el7
- Resolves: #1438731 Extend ipa-server-certinstall and ipa-certupdate to
  handle PKINIT certificates/anchors
  - certdb: add named trust flag constants
  - certdb, certs: make trust flags argument mandatory
  - certdb: use custom object for trust flags
  - install: trust IPA CA for PKINIT
  - client install: fix client PKINIT configuration
  - install: introduce generic Kerberos Augeas lens
  - server install: fix KDC PKINIT configuration
  - ipapython.ipautil.run: Add option to set umask before executing command
  - certs: do not export keys world-readable in install_key_from_p12
  - certs: do not export CA certs in install_pem_from_p12
  - server install: fix KDC certificate validation in CA-less
  - replica install: respect --pkinit-cert-file
  - cacert manage: support PKINIT
  - server certinstall: support PKINIT
- Resolves: #1444432 CA-less pkinit not installable with --pkinit-cert-file
  option
  - certs: do not export CA certs in install_pem_from_p12
  - server install: fix KDC certificate validation in CA-less
- Resolves: #1451228 ipa-kra-install fails when primary KRA server has been
  decommissioned
  - ipa-kra-install: fix pkispawn setting for pki_security_domain_hostname
- Resolves: #1451712 KRA installation fails on server that was originally
  installed as CA-less
  - ipa-ca-install: append CA cert chain into /etc/ipa/ca.crt
- Resolves: #1441499 ipa cert-show does not raise error if no file name
  specified
  - ca/cert-show: check certificate_out in options
- Resolves: #1449522 Deprecate `ipa pkinit-anonymous` command in FreeIPA 4.5+
  - Remove pkinit-anonymous command
- Resolves: #1449523 Provide an API command to retrieve PKINIT status
  in the FreeIPA topology
  - Allow for multivalued server attributes
  - Refactor the role/attribute member reporting code
  - Add an attribute reporting client PKINIT-capable servers
  - Add the list of PKINIT servers as a virtual attribute to global config
  - Add `pkinit-status` command
  - test_serverroles: Get rid of MockLDAP and use ldap2 instead
- Resolves: #1452216 Replica installation grants HTTP principal access in WebUI
  - Fix rare race condition with missing ccache file
- Resolves: #1455045 Simple service uninstallers must be able to handle
  missing service files gracefully
  - only stop/disable simple service if it is installed
- Resolves: #1455541 after upgrade login from web ui breaks
  - krb5: make sure KDC certificate is readable
- Resolves: #1455862 "ipa: ERROR: an internal error has occurred" on executing
  command "ipa cert-request --add" after upgrade
  - Change python-cryptography to python2-cryptography

* Thu May 18 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-13.el7
- Resolves: #1451804 "AttributeError: 'tuple' object has no attribute 'append'"
  error observed during ipa upgrade with latest package.
  - ipa-server-install: fix uninstall
- Resolves: #1445390 ipa-[ca|kra]-install with invalid DM password break
  replica
  - ca install: merge duplicated code for DM password
  - installutils: add DM password validator
  - ca, kra install: validate DM password

* Tue May 16 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-12.el7
- Resolves: #1447284 Upgrade from ipa-4.1 fails when enabling KDC proxy
  - python2-ipalib: add missing python dependency
  - installer service: fix typo in service entry
  - upgrade: add missing suffix to http instance
- Resolves: #1444791 Update man page of ipa-kra-install
  - ipa-kra-install manpage: document domain-level 1
- Resolves: #1441493 ipa cert-show raises stack traces when
  --certificate-out=/tmp
  - cert-show: writable files does not mean dirs
- Resolves: #1441192 Add the name of URL parameter which will be check for
  username during cert login
  - Bump version of ipa.conf file
- Resolves: #1378797 Web UI must check OCSP and CRL during smartcard login
  - Turn on NSSOCSP check in mod_nss conf
- Resolves: #1322963 Errors from AD when trying to sign ipa.csr, conflicting
  template on
  - renew agent: respect CA renewal master setting
  - server upgrade: always fix certmonger tracking request
  - cainstance: use correct profile for lightweight CA certificates
  - renew agent: allow reusing existing certs
  - renew agent: always export CSR on IPA CA certificate renewal
  - renew agent: get rid of virtual profiles
  - ipa-cacert-manage: add --external-ca-type
- Resolves: #1441593 error adding authenticator indicators to host
  - Fixing adding authenticator indicators to host
- Resolves: #1449525 Set directory ownership in spec file
  - Added plugins directory to ipaclient subpackages
  - ipaclient: fix missing RPM ownership
- Resolves: #1451279 otptoken-add-yubikey KeyError: 'ipatokenotpdigits'
  - otptoken-add-yubikey: When --digits not provided use default value

* Wed May 10 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-11.el7
- Resolves: #1449189 ipa-kra-install timeouts on replica
  - ipa-kra-install: fix check_host_keys

* Wed May  3 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-10.el7
- Resolves: #1438833 [ipa-replica-install] - 406 Client Error: Failed to
  validate message: Incorrect number of results (0) searching forpublic key for
  host
  - Make sure remote hosts have our keys
- Resolves: #1442815 Replica install fails during migration from older IPA
  master
  - Refresh Dogtag RestClient.ca_host property
  - Remove the cachedproperty class
- Resolves: #1444787 Update warning message when KRA installation fails
  - kra install: update installation failure message
- Resolves: #1444896 ipa-server-install with external-ca fails in FIPS mode
  - ipa-server-install with external CA: fix pkinit cert issuance
- Resolves: #1445397 GET in KerberosSession.finalize_kerberos_acquisition()
  must use FreeIPA CA
  - kerberos session: use CA cert with full cert chain for obtaining cookie
- Resolves: #1447375 ipa-client-install: extra space in pkinit_anchors
  definition
  - ipa-client-install: remove extra space in pkinit_anchors definition
- Resolves: #1447703 Fix SELinux contex of http.keytab during upgrade
  - Use proper SELinux context with http.keytab

* Fri Apr 28 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-9.el7
- Resolves: #1200767 [RFE] Allow Kerberos authentication for users with
  certificates on smart cards (pkinit)
  - spec file: bump krb5 Requires for certauth fixes
- Resolves: #1438729 Configure local PKINIT on DL0 or when '--no-pkinit' option
  is used
  - separate function to set ipaConfigString values on service entry
  - Allow for configuration of all three PKINIT variants when deploying KDC
  - API for retrieval of master's PKINIT status and publishing it in LDAP
  - Use only anonymous PKINIT to fetch armor ccache
  - Stop requesting anonymous keytab and purge all references of it
  - Use local anchor when armoring password requests
  - Upgrade: configure local/full PKINIT depending on the master status
  - Do not test anonymous PKINIT after install/upgrade
- Resolves: #1442427 ipa.ipaserver.install.plugins.adtrust.
  update_tdo_gidnumber: ERROR Default SMB Group not found
  - upgrade: adtrust update_tdo_gidnumber plugin must check if adtrust is
    installed
- Resolves: #1442932 ipa restore fails to restore IPA user
  - restore: restart/reload gssproxy after restore
- Resolves: #1444896 ipa-server-install with external-ca fails in FIPS mode
  - Fix CA/server cert validation in FIPS
- Resolves: #1444947 Deadlock between topology and schema-compat plugins
  - compat-manage: behave the same for all users
  - Move the compat plugin setup at the end of install
  - compat: ignore cn=topology,cn=ipa,cn=etc subtree
- Resolves: #1445358 ipa vault-add raises TypeError
  - vault: piped input for ipa vault-add fails
- Resolves: #1445382 ipa vault-retrieve fails to retrieve data from vault
  - Vault: Explicitly default to 3DES CBC
- Resolves: #1445432 uninstall ipa client automount failed with RuntimeWarning
  - automount install: fix checking of SSSD functionality on uninstall
- Resolves: #1446137 pki_client_database_password is shown in
  ipaserver-install.log
  - Hide PKI Client database password in log file

* Thu Apr 20 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-8.el7
- Resolves: #1443869 Command "openssl pkcs12 ..." failed during IPA upgrade
  - Fix CAInstance.import_ra_cert for empty passwords

* Wed Apr 19 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-7.el7
- Resolves: #1431520 ipa cert-find runs a large number of searches, so IPA
  WebUI is slow to display user details page
  - cert: defer cert-find result post-processing
- Resolves: #1435611 Tracebacks seen from dogtag-ipa-ca-renew-agent-submit
  helper when installing replica
  - server-install: No double Kerberos install
- Resolves: #1437502 ipa-replica-install fails with requirement to
  use --force-join that is a client install option.
  - Add the force-join option to replica install
  - replicainstall: better client install exception handling
- Resolves: #1437953 Server CA-less impossible option check
  - server-install: remove broken no-pkinit check
- Resolves: #1441160 FreeIPA client <= 4.4 fail to parse 4.5 cookies
  - Add debug log in case cookie retrieval went wrong
- Resolves: #1441548 ipa server install fails with --external-ca option
  - ext. CA: correctly write the cert chain
- Resolves: #1441718 Conversion of CA-less server to CA fails on CA instance
  spawn
  - Fix CA-less to CA-full upgrade
- Resolves: #1442133 Do not link libkrad, liblber, libldap_r and
  libsss_nss_idmap to every binary in IPA
  - configure: fix AC_CHECK_LIB usage
- Resolves: #1442815 Replica install fails during migration from older IPA
  master
  - Fix RA cert import during DL0 replication
- Related: #1442004 Building IdM/FreeIPA internally on all architectures -
  filtering unsupported packages
  - Build all subpackages on all architectures

* Wed Apr 12 2017 Pavel Vomacka <pvomacka@redhat.com> - 4.5.0-6.el7
- Resolves: #1382053 Need to have validation for idrange names
  - idrange-add: properly handle empty --dom-name option
- Resolves: #1435611 Tracebacks seen from dogtag-ipa-ca-renew-agent-submit
  helper when installing replica
  - dsinstance: reconnect ldap2 after DS is restarted by certmonger
  - httpinstance: avoid httpd restart during certificate request
  - dsinstance, httpinstance: consolidate certificate request code
  - install: request service certs after host keytab is set up
  - renew agent: revert to host keytab authentication
  - renew agent, restart scripts: connect to LDAP after kinit
- Resolves: #1436987 ipasam: gidNumber attribute is not created in the trusted
  domain entry
  - ipa-sam: create the gidNumber attribute in the trusted domain entry
  - Upgrade: add gidnumber to trusted domain entry
- Resolves: #1438679 [ipa-replica-install] - IncorrectPasswordException:
  Incorrect client security database password
  - Add pki_pin only when needed
- Resolves: #1438348 Console output message while adding trust should be
  mapped with texts changed in Samba.
  - ipaserver/dcerpc: unify error processing
- Resolves: #1438366 ipa trust-fetch-domains: ValidationError: invalid
  'Credentials': Missing credentials for cross-forest communication
  - trust: always use oddjobd helper for fetching trust information
- Resolves: #1441192 Add the name of URL parameter which will be check for
  username during cert login
  - WebUI: cert login: Configure name of parameter used to pass username
- Resolves: #1437879 [copr] Replica install failing
  - Create system users for FreeIPA services during package installation
- Resolves: #1441316 WebUI cert auth fails after ipa-adtrust-install
  - Fix s4u2self with adtrust

* Wed Apr  5 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-5.el7
- Resolves: #1318186 Misleading error message during external-ca IPA master
  install
  - httpinstance: make sure NSS database is backed up
- Resolves: #1331443 Re-installing ipa-server after uninstall fails with "ERROR
  CA certificate chain in ... incomplete"
  - httpinstance: make sure NSS database is backed up
- Resolves: #1393726 Enumerate all available request type options in ipa
  cert-request help
  - Hide request_type doc string in cert-request help
- Resolves: #1402959 [RFE] Universal Smart Card to Identity mapping
  - spec file: bump libsss_nss_idmap-devel BuildRequires
  - server: make sure we test for sss_nss_getlistbycert
- Resolves: #1437378 ipa-adtrust-install produced an error and failed on
  starting smb when hostname is not FQDN
  - adtrust: make sure that runtime hostname result is consistent with the
    configuration
- Resolves: #1437555 ipa-replica-install with DL0 fails to get annonymous
  keytab
  - Always check and create anonymous principal during KDC install
  - Remove duplicate functionality in upgrade
- Resolves: #1437946 Upgrade to FreeIPA 4.5.0 does not configure anonymous
  principal for PKINIT
  - Upgrade: configure PKINIT after adding anonymous principal
  - Remove unused variable from failed anonymous PKINIT handling
  - Split out anonymous PKINIT test to a separate method
  - Ensure KDC is propery configured after upgrade
- Resolves: #1437951 Remove pkinit-related options from server/replica-install
  on DL0
  - Fix the order of cert-files check
  - Don't allow setting pkinit-related options on DL0
  - replica-prepare man: remove pkinit option refs
  - Remove redundant option check for cert files
- Resolves: #1438490 CA-less installation fails on publishing CA certificate
  - Get correct CA cert nickname in CA-less
  - Remove publish_ca_cert() method from NSSDatabase
- Resolves: #1438838 Avoid arch-specific path in /etc/krb5.conf.d/ipa-certmap
  - IPA-KDB: use relative path in ipa-certmap config snippet
- Resolves: #1439038 Allow erasing ipaDomainResolutionOrder attribute
  - Allow erasing ipaDomainResolutionOrder attribute

* Wed Mar 29 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-4.el7
- Resolves: #1434032 Run ipa-custodia with custom SELinux context
  - Require correct custodia version

* Tue Mar 28 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-3.el7
- Resolves: #800545 [RFE] Support SUDO command rename
  - Reworked the renaming mechanism
  - Allow renaming of the sudorule objects
- Resolves: #872671 IPA WebUI login for AD Trusted User fails
  - WebUI: check principals in lowercase
  - WebUI: add method for disabling item in user dropdown menu
  - WebUI: Add support for login for AD users
- Resolves: #1200767 [RFE] Allow Kerberos authentication for users with
  certificates on smart cards (pkinit)
  - ipa-kdb: add ipadb_fetch_principals_with_extra_filter()
  - IPA certauth plugin
  - ipa-kdb: do not depend on certauth_plugin.h
  - spec file: bump krb5-devel BuildRequires for certauth
- Resolves: #1264370 RFE: disable last successful authentication by default in
  ipa.
  - Set "KDC:Disable Last Success" by default
- Resolves: #1318186 Misleading error message during external-ca IPA master
  install
  - certs: do not implicitly create DS pin.txt
  - httpinstance: clean up /etc/httpd/alias on uninstall
- Resolves: #1331443 Re-installing ipa-server after uninstall fails with "ERROR
  CA certificate chain in ... incomplete"
  - certs: do not implicitly create DS pin.txt
  - httpinstance: clean up /etc/httpd/alias on uninstall
- Resolves: #1366572 [RFE] Web UI: allow Smart Card authentication
  - configure: fix --disable-server with certauth plugin
  - rpcserver.login_x509: Actually return reply from __call__ method
  - spec file: Bump requires to make Certificate Login in WebUI work
- Resolves: #1402959 [RFE] Universal Smart Card to Identity mapping
  - extdom: do reverse search for domain separator
  - extdom: improve cert request
- Resolves: #1430363 [RFE] HBAC rule names command rename
  - Reworked the renaming mechanism
  - Allow renaming of the HBAC rule objects
- Resolves: #1433082 systemctl daemon-reload needs to be called after
  httpd.service.d/ipa.conf is manipulated
  - tasks: run `systemctl daemon-reload` after httpd.service.d updates
- Resolves: #1434032 Run ipa-custodia with custom SELinux context
  - Use Custodia 0.3.1 features
- Resolves: #1434384 RPC client should use HTTP persistent connection
  - Use connection keep-alive
  - Add debug logging for keep-alive
  - Increase Apache HTTPD's default keep alive timeout
- Resolves: #1434729 man ipa-cacert-manage install needs clarification
  - man ipa-cacert-manage install needs clarification
- Resolves: #1434910 replica install against IPA v3 master fails with ACIError
  - Fixing replica install: fix ldap connection in domlvl 0
- Resolves: #1435394 Ipa-kra-install fails with weird output when backspace is
  used during typing Directory Manager password
  - ipapython.ipautil.nolog_replace: Do not replace empty value
- Resolves: #1435397 ipa-replica-install can't install replica file produced by
  ipa-replica-prepare on 4.5
  - replica prepare: fix wrong IPA CA nickname in replica file
- Resolves: #1435599 WebUI: in self-service Vault menu item is shown even if
  KRA is not installed
  - WebUI: Fix showing vault in selfservice view
- Resolves: #1435718 As a ID user I cannot call a command with --rights option
  - ldap2: use LDAP whoami operation to retrieve bind DN for current connection
- Resolves: #1436319 "Truncated search results" pop-up appears in user details
  in WebUI
  - WebUI: Add support for suppressing warnings
  - WebUI: suppress truncation warning in select widget
- Resolves: #1436333 Uninstall fails with No such file or directory:
  '/var/run/ipa/services.list'
  - Create temporaty directories at the begining of uninstall
- Resolves: #1436334 WebUI: Adding certificate mapping data using certificate
  fails
  - WebUI: Allow to add certs to certmapping with CERT LINES around
- Resolves: #1436338 CLI doesn't work after ipa-restore
  - Backup ipa-specific httpd unit-file
  - Backup CA cert from kerberos folder
- Resolves: #1436342 Bump samba version, required for FIPS mode and privilege
  separation
  - Bump samba version for FIPS and priv. separation
- Resolves: #1436642 [ipalib/rpc.py] - "maximum recursion depth exceeded" with
  ipa vault commands
  - Avoid growing FILE ccaches unnecessarily
  - Handle failed authentication via cookie
  - Work around issues fetching session data
  - Prevent churn on ccaches
- Resolves: #1436657 Add workaround for pki_pin for FIPS
  - Generate PIN for PKI to help Dogtag in FIPS
- Resolves: #1436714 [vault] cache KRA transport cert
  - Simplify KRA transport cert cache
- Resolves: #1436723 cert-find does not find all certificates without
  sizelimit=0
  - cert: do not limit internal searches in cert-find
- Resolves: #1436724 Renewal of IPA RA fails on replica
  - dogtag-ipa-ca-renew-agent-submit: fix the is_replicated() function
- Resolves: #1436753 Master tree fails to install
  - httpinstance.disable_system_trust: Don't fail if module 'Root Certs' is not
    available

* Tue Mar 21 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-2.el7
- Resolves: #1432630 python2-jinja2 needed for python2-ipaclient
  - Remove csrgen
- Resolves: #1432903 Set GssProxy options to enable caching of ldap tickets
  - Add options to allow ticket caching

* Wed Mar 15 2017 Jan Cholasta <jcholast@redhat.com> - 4.5.0-1.el7
- Resolves: #828866 [RFE] enhance --subject option for ipa-server-install
- Resolves: #1160555 ipa-server-install: Cannot handle double hyphen "--" in
  hostname
- Resolves: #1286288 Insufficient 'write' privilege to the 'ipaExternalMember'
  attribute
- Resolves: #1321652 ipa-server-install fails when using external certificates
  that encapsulate RDN components in double quotes
- Resolves: #1327207 ipa cert-revoke --help doesn't provide enough info on
  revocation reasons
- Resolves: #1340880 ipa-server-install: improve prompt on interactive
  installation
- Resolves: #1353841 ipa-replica-install fails to install when resolv.conf
  incomplete entries
- Resolves: #1356104 cert-show command does not display Subject Alternative
  Names
- Resolves: #1357511 Traceback message seen when ipa is provided with invalid
  configuration file name
- Resolves: #1358752 ipa-ca-install fails on replica when IPA server is
  converted from CA-less to CA-full
- Resolves: #1366572 [RFE] Web UI: allow Smart Card authentication
- Resolves: #1367572 improve error message in ipa migrate-ds: mention ipa
  config-mod --enable-migration=TRUE
- Resolves: #1367868 Add options to retrieve lightweight CA certificate/chain
- Resolves: #1371927 Implement ca-enable/disable commands.
- Resolves: #1372202 Add Users into User Group editors fails to show Full names
- Resolves: #1373091 Adding an auth indicator from the CLI creates an extra
  check box in the UI
- Resolves: #1375596 Ipa-server WebUI - long user/group name show wrong error
  message
- Resolves: #1375905 "Normal" group type in the UI is confusing
- Resolves: #1376040 IPA client ipv6 - invalid --ip-address shows traceback
- Resolves: #1376630 IDM admin password gets written to
  /root/.dogtag/pki-tomcat/ca/pkcs12_password.conf
- Resolves: #1376729 ipa-server-install script option --no_hbac_allow should
  match other options
- Resolves: #1378461 IPA Allows Password Reuse with History value defined when
  admin resets the password.
- Resolves: #1379029 conncheck failing intermittently during single step
  replica installs
- Resolves: #1379858 [RFE] better debugging for ipa-replica-conncheck
- Resolves: #1384310 ipa dnsrecord-add fails with Keyerror stack trace
- Resolves: #1392778 Update man page for ipa-adtrust-install by
  removing --no-msdcs option
- Resolves: #1392858 Rebase to FreeIPA 4.5+
  - Rebase to 4.5.0
- Resolves: #1399133 Delete option shouldn't be available for hosts applied to
  view.
- Resolves: #1399190 [RFE] Certificates issued by externally signed IdM CA
  should contain full trust chain
- Resolves: #1400416 RFE: Provide option to take backup of IPA server before
  uninstalling IPA server
- Resolves: #1400529 cert-request is not aware of Kerberos principal aliases
- Resolves: #1401526 IPA WebUI certificates are grayed out on overview page but
  not on details page
- Resolves: #1402959 [RFE] Universal Smart Card to Identity mapping
- Resolves: #1404750 ipa-client-install fails to get CA cert via LDAP when
  non-FQDN name of IPA server is first in /etc/hosts
- Resolves: #1409628 [RFE] Semi-automatic integration with external DNS using
  nsupdate
- Resolves: #1413742 Backport request for bug/issue Change IP address
  validation errors to warnings
- Resolves: #1415652 IPA replica install log shows password in plain text
- Resolves: #1427897 different behavior regarding system wide certs in master
  and replica.
- Resolves: #1430314 The ipa-managed-entries command failed, exception:
  AttributeError: ldap2

* Tue Mar 14 2017 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14.7
- Resolves: #1419735 ipa-replica-install fails promotecustodia.create_replica
  with cert errors (untrusted)
  - added ssl verification using IPA trust anchor
- Resolves: #1428472 batch param compatibility is incorrect
  - compat: fix `Any` params in `batch` and `dnsrecord`
- Renamed patches 1011 and 1012 to 0159 and 0157, as they were merged upstream

* Tue Jan 31 2017 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14.6
- Resolves: #1416454 replication race condition prevents IPA to install
  - wait_for_entry: use only DN as parameter
  - Wait until HTTPS principal entry is replicated to replica
  - Use proper logging for error messages

* Tue Jan 31 2017 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14.5
- Resolves: #1365858 ipa-ca-install fails on replica when IPA Master is
  installed without CA
  - Set up DS TLS on replica in CA-less topology
- Resolves: #1398600 IPA replica install fails with dirsrv errors.
  - Do not configure PKI ajp redirection to use "::1"
- Resolves: #1413137 CVE-2017-2590 ipa: Insufficient permission check for
  ca-del, ca-disable and ca-enable commands
  - ca: correctly authorise ca-del, ca-enable and ca-disable

* Fri Dec 16 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14.4
- Resolves: #1370493 CVE-2016-7030 ipa: DoS attack against kerberized services
  by abusing password policy
  - ipa-kdb: search for password policies globally
- Renamed patches 1011 and 1012 to 0151 and 0150, as they were merged upstream

* Tue Dec 13 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14.3
- Resolves: #1398670 Check IdM Topology for broken record caused by replication
  conflict before upgrading it
  - Check for conflict entries before raising domain level

* Tue Dec 13 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14.2
- Resolves: #1382812 Creation of replica for disconnected environment is
  failing with CA issuance errors; Need good steps.
  - gracefully handle setting replica bind dn group on old masters
- Resolves: #1397439 ipa-ca-install on promoted replica hangs on creating a
  temporary CA admin
  - replication: ensure bind DN group check interval is set on replica config
  - add missing attribute to ipaca replica during CA topology update
- Resolves: #1401088 IPA upgrade of replica without DNS fails during restart of
  named-pkcs11
  - bindinstance: use data in named.conf to determine configuration status

* Mon Dec 12 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14.1
- Resolves: #1370493 CVE-2016-7030 ipa: DoS attack against kerberized services
  by abusing password policy
  - password policy: Add explicit default password policy for hosts and
    services
- Resolves: #1395311 CVE-2016-9575 ipa: Insufficient permission check in
  certprofile-mod
  - certprofile-mod: correctly authorise config update

* Tue Nov  1 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-14
- Resolves: #1378353 Replica install fails with old IPA master sometimes during
  replication process
  - spec file: bump minimal required version of 389-ds-base
- Resolves: #1387779 Make httpd publish CA certificate on Domain Level 1
  - Fix missing file that fails DL1 replica installation
- Resolves: #1387782 WebUI: Services are not displayed correctly after upgrade
  - WebUI: services without canonical name are shown correctly
- Resolves: #1389709 Traceback seen in error_log when trustdomain-del is run
  - trustdomain-del: fix the way how subdomain is searched

* Mon Oct 31 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-13
- Resolves: #1318616 CA fails to start after doing ipa-ca-install --external-ca
  - Keep NSS trust flags of existing certificates
- Resolves: #1360813 ipa-server-certinstall does not update all certificate
  stores and doesn't set proper trust permissions
  - Add cert checks in ipa-server-certinstall
- Resolves: #1371479 cert-find --all does not show information about revocation
  - cert: add revocation reason back to cert-find output
- Resolves: #1375133 WinSync users who have First.Last casing creates users who
  can have their password set
  - ipa passwd: use correct normalizer for user principals
- Resolves: #1377858 Users with 2FA tokens are not able to login to IPA servers
  - Properly handle LDAP socket closures in ipa-otpd
- Resolves: #1387779 Make httpd publish CA certificate on Domain Level 1
  - Make httpd publish its CA certificate on DL1

* Fri Sep 16 2016 Petr Vobornik <pvoborni@redhat.com> - 4.4.0-12
- Resolves: #1373910 IPA server upgrade fails with DNS timed out errors.
- Resolves: #1375269 ipa trust-fetch-domains throws internal error

* Tue Sep 13 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-11
- Resolves: #1373359 ipa-certupdate fails with "CA is not configured"
  - Fix regression introduced in ipa-certupdate

* Wed Sep  7 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-10
- Resolves: #1355753 adding two way non transitive(external) trust displays
  internal error on the console
  - Always fetch forest info from root DCs when establishing two-way trust
  - factor out `populate_remote_domain` method into module-level function
  - Always fetch forest info from root DCs when establishing one-way trust
- Resolves: #1356101 Lightweight sub-CA certs are not tracked by certmonger
  after `ipa-replica-install`
  - Track lightweight CAs on replica installation
- Resolves: #1357488 ipa command stuck forever on higher versioned client with
  lower versioned server
  - compat: Save server's API version in for pre-schema servers
  - compat: Fix ping command call
  - schema cache: Store and check info for pre-schema servers
- Resolves: #1363905 man page for ipa-replica-manage has a typo in -c flag
  - Fix man page ipa-replica-manage: remove duplicate -c option
    from --no-lookup
- Resolves: #1367865 webui: cert_revoke should use --cacn to set correct CA
  when revoking certificate
  - cert: include CA name in cert command output
  - WebUI add support for sub-CAs while revoking certificates
- Resolves: #1368424 Unable to view certificates issued by Sub CA in Web UI
  - Add support for additional options taken from table facet
  - WebUI: Fix showing certificates issued by sub-CA
- Resolves: #1368557 dnsrecord-add does not prompt for missing record parts
  internactively
  - dns: normalize record type read interactively in dnsrecord_add
  - dns: prompt for missing record parts in CLI
  - dns: fix crash in interactive mode against old servers
- Resolves: #1370519 Certificate revocation in service-del and host-del isn't
  aware of Sub CAs
  - cert: fix cert-find --certificate when the cert is not in LDAP
  - Make host/service cert revocation aware of lightweight CAs
- Resolves: #1371901 Use OAEP padding with custodia
  - Use RSA-OAEP instead of RSA PKCS#1 v1.5
- Resolves: #1371915 When establishing external two-way trust, forest root
  Administrator account is used to fetch domain info
  - do not use trusted forest name to construct domain admin principal
- Resolves: #1372597 Incorrect CA ACL evaluation of SAN DNS names in
  certificate request
  - Fix CA ACL Check on SubjectAltNames
- Resolves: #1373272 CLI always sends default command version
  - cli: use full name when executing a command
- Resolves: #1373359 ipa-certupdate fails with "CA is not configured"
  - Fix ipa-certupdate for CA-less installation
- Resolves: #1373540 client-install with IPv6 address fails on link-local
  address (always)
  - Fix parse errors with link-local addresses

* Fri Sep  2 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-9
- Resolves: #1081561 CA not start during ipa server install in pure IPv6 env
  - Fix ipa-server-install in pure IPv6 environment
- Resolves: #1318169 Tree-root domains in a trusted AD forest aren't marked as
  reachable via the forest root
  - trust: make sure ID range is created for the child domain even if it exists
  - ipa-kdb: simplify trusted domain parent search
- Resolves: #1335567 Update Warning in IdM Web UI API browser
  - WebUI: add API browser is tech preview warning
- Resolves: #1348560 Mulitple domain Active Directory Trust conflict
  - ipaserver/dcerpc: reformat to make the code closer to pep8
  - trust: automatically resolve DNS trust conflicts for triangle trusts
- Resolves: #1351593 CVE-2016-5404 ipa: Insufficient privileges check in
  certificate revocation
  - cert-revoke: fix permission check bypass (CVE-2016-5404)
- Resolves: #1353936 custodia.conf and server.keys file is world-readable.
  - Remove Custodia server keys from LDAP
  - Secure permissions of Custodia server.keys
- Resolves: #1358752 ipa-ca-install fails on replica when IPA server is
  converted from CA-less to CA-full
  - custodia: include known CA certs in the PKCS#12 file for Dogtag
  - custodia: force reconnect before retrieving CA certs from LDAP
- Resolves: #1362333 ipa vault container owner cannot add vault
  - Fix: container owner should be able to add vault
- Resolves: #1365546 External trust with root domain is transitive
  - trust: make sure external trust topology is correctly rendered
- Resolves: #1365572 IPA server broken after upgrade
  - Require pki-core-10.3.3-7
- Resolves: #1367864 Server assumes latest version of command instead of
  version 1 for old / 3rd party clients
  - rpcserver: assume version 1 for unversioned command calls
  - rpcserver: fix crash in XML-RPC system commands
- Resolves: #1367773 thin client ignores locale change
  - schema cache: Fallback to 'en_us' when locale is not available
- Resolves: #1368754 ipa server uninstall fails with Python "Global Name error"
  - Fail on topology disconnect/last role removal
- Resolves: #1368981 ipa otptoken-add --type=hotp --key creates wrong OTP
  - otptoken, permission: Convert custom type parameters on server
- Resolves: #1369414 ipa server-del fails with Python stack trace
  - Handled empty hostname in server-del command
- Resolves: #1369761 ipa-server must depend on a version of httpd that support
  mod_proxy with UDS
  - Require httpd 2.4.6-31 with mod_proxy Unix socket support
- Resolves: #1370512 Received ACIError instead of DuplicatedError in
  stageuser_tests
  - Raise DuplicatedEnrty error when user exists in delete_container
- Resolves: #1371479 cert-find --all does not show information about revocation
  - cert: add missing param values to cert-find output
- Renamed patch 1011 to 0100, as it was merged upstream

* Wed Aug 17 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-8
- Resolves: #1298288 [RFE] Improve performance in large environments.
  - cert: speed up cert-find
- Resolves: #1317379 [EXPERIMENTAL][RFE] Web UI: allow Smart Card
  authentication
  - service: add flag to allow S4U2Self
  - Add 'trusted to auth as user' checkbox
  - Added new authentication method
- Resolves: #1353881 ipa-replica-install suggests about
  non-existent --force-ntpd option
  - Don't show --force-ntpd option in replica install
- Resolves: #1354441 DNS forwarder check is too strict: unable to add
  sub-domain to already-broken domain
  - DNS: allow to add forward zone to already broken sub-domain
- Resolves: #1356146 performance regression in CLI help
  - schema: Speed up schema cache
  - frontend: Change doc, summary, topic and NO_CLI to class properties
  - schema: Introduce schema cache format
  - schema: Generate bits for help load them on request
  - help: Do not create instances to get information about commands and topics
  - schema cache: Do not reset ServerInfo dirty flag
  - schema cache: Do not read fingerprint and format from cache
  - Access data for help separately
  - frontent: Add summary class property to CommandOverride
  - schema cache: Read server info only once
  - schema cache: Store API schema cache in memory
  - client: Do not create instance just to check isinstance
  - schema cache: Read schema instead of rewriting it when SchemaUpToDate
- Resolves: #1360769 ipa-server-certinstall couldnt unlock private key file
  - server install: do not prompt for cert file PIN repeatedly
- Resolves: #1364113 ipa-password: ipa: ERROR: RuntimeError: Unable to create
  cache directory: [Errno 13] Permission denied: '/home/test_user'
  - schema: Speed up schema cache
- Resolves: #1366604 `cert-find` crashes on invalid certificate data
  - cert: do not crash on invalid data in cert-find
- Resolves: #1366612 Middle replica uninstallation in line topology works
  without '--ignore-topology-disconnect'
  - Fail on topology disconnect/last role removal
- Resolves: #1366626 caacl-add-service: incorrect error message when service
  does not exists
  - Fix ipa-caalc-add-service error message
- Resolves: #1367022 The ipa-server-upgrade command failed when named-pkcs11
  does not happen to run during dnf upgrade
  - DNS server upgrade: do not fail when DNS server did not respond
- Resolves: #1367759 [RFE] [webui] warn admin if there is only one IPA server
  with CA
  - Add warning about only one existing CA server
  - Set servers list as default facet in topology facet group
- Resolves: #1367773 thin client ignores locale change
  - schema check: Check current client language against cached one

* Wed Aug 10 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-7
- Resolves: #1361119 UPN-based search for AD users does not match an entry in
  slapi-nis map cache
  - support multiple uid values in schema compatibility tree

* Wed Aug 10 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-6
- Resolves: #1309700 Process /usr/sbin/winbindd was killed by signal 6
  - Revert "spec: add conflict with bind-chroot to freeipa-server-dns"
- Resolves: #1341249 Subsequent external CA installation fails
  - install: fix external CA cert validation
- Resolves: #1353831 ipa-server-install fails in container because of
  hostnamectl set-hostname
  - server-install: Fix --hostname option to always override api.env values
  - install: Call hostnamectl set-hostname only if --hostname option is used
- Resolves: #1356091 ipa-cacert-manage --help and man differ
  - Improvements for the ipa-cacert-manage man and help
- Resolves: #1360631 ipa-backup is not keeping the
  /etc/tmpfiles.d/dirsrv-<instance>.conf
  - ipa-backup: backup /etc/tmpfiles.d/dirsrv-<instance>.conf
- Resolves: #1361047 ipa-replica-install --help usage line suggests the replica
  file is needed
  - Update ipa-replica-install documentation
- Resolves: #1361545 ipa-client-install starts rhel-domainname.service but does
  not rpm-require it
  - client: RPM require initscripts to get *-domainname.service
- Resolves: #1364197 caacl: error when instantiating rules with service
  principals
  - caacl: fix regression in rule instantiation
- Resolves: #1364310 ipa otptoken-add bytes object has no attribute confirm
  - parameters: move the `confirm` kwarg to Param
- Resolves: #1364464 Topology graph: ca and domain adders shows question marks
  instead of plus icon
  - Fix unicode characters in ca and domain adders
- Resolves: #1365083 Incomplete output returned for command ipa vault-add
  - client: add missing output params to client-side commands
- Resolves: #1365526 build fails during "make check"
  - ipa-kdb: Fix unit test after packaging changes in krb5

* Fri Aug  5 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-5
- Resolves: #1353829 traceback message seen in ipaserver-uninstall.log file.
  - Do not initialize API in ipa-client-automount uninstall
- Resolves: #1356899 com.redhat.idm.trust.fetch_domains need update after thin
  client changes
  - idrange: fix unassigned global variable
- Resolves: #1360792 Migrating users doesn't update krbCanonicalName
  - re-set canonical principal name on migrated users
- Resolves: #1362012 ipa hbactest produces error about cannot concatenate 'str'
  and 'bool' objects
  - Fix ipa hbactest output
- Resolves: #1362260 ipa vault-mod no longer allows defining salt
  - vault: add missing salt option to vault_mod
- Resolves: #1362312 ipa vault-retrieve internal error when using the wrong
  public key
  - vault: Catch correct exception in decrypt
- Resolves: #1362537 ipa-server-install fails to create symlink from
  /etc/ipa/kdcproxy/ to /etc/httpd/conf.d/
  - Correct path to HTTPD's systemd service directory
- Resolves: #1363756 Increase length of passwords generated by installer
  - Increase default length of auto generated passwords

* Fri Jul 29 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-4
- Resolves: #1117306 [RFE] Allow multiple Principals per host entry (Kerberos
  aliases)
  - harden the check for trust namespace overlap in new principals
- Resolves: #1351142 CLI is not using session cookies for communication with
  IPA API
  - Fix session cookies
- Resolves: #1353888 Fix the help for ipa otp and other topics
  - help: Add dnsserver commands to help topic 'dns'
- Resolves: #1354406 host-del updatedns options complains about missing ptr
  record for host
  - Host-del: fix behavior of --updatedns and PTR records
- Resolves: #1355718 ipa-replica-manage man page example output differs actual
  command output
  - Minor fix in ipa-replica-manage MAN page
- Resolves: #1358229 Traceback message should be fixed, seen while editing
  winsync migrated user information in Default trust view.
  - baseldap: Fix MidairCollision instantiation during entry modification
- Resolves: #1358849 CA replica install logs to wrong log file
  - unite log file name of ipa-ca-install
- Resolves: #1359130 ipa-server-install command fails to install IPA server.
  - DNS Locations: fix update-system-records unpacking error
- Resolves: #1359237 AVC on dirsrv config caused by IPA installer
  - Use copy when replacing files to keep SELinux context
- Resolves: #1359692 ipa-client-install join fail with traceback against
  RHEL-6.8 ipa-server
  - compat: fix ping call
- Resolves: #1359738 ipa-replica-install --domain=<IPA primary domain> option
  does not work
  - replica-install: Fix --domain
- Resolves: #1360778 Vault commands are available in CLI even when the server
  does not support them
  - Revert "Enable vault-* commands on client"
  - client: fix hiding of commands which lack server support
- Related: #1281704 Rebase to softhsm 2.1.0
  - Remove the workaround for softhsm bug #1293340
- Related: #1298288 [RFE] Improve performance in large environments.
  - Create indexes for krbCanonicalName attribute

* Fri Jul 22 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-3
- Resolves: #1296140 Remove redhat-access-plugin-ipa support
  - Obsolete and conflict redhat-access-plugin-ipa
- Resolves: #1351119 Multiple issues while uninstalling ipa-server
  - server uninstall fails to remove krb principals
- Resolves: #1351758 ipa commands not showing expected error messages
  - frontend: copy command arguments to output params on client
  - Show full error message for selinuxusermap-add-hostgroup
- Resolves: #1352883 Traceback on adding default automember group and hostgroup
  set
  - allow 'value' output param in commands without primary key
- Resolves: #1353888 Fix the help for ipa otp and other topics
  - schema: Fix subtopic -> topic mapping
- Resolves: #1354348 ipa trustconfig-show throws internal error.
  - allow 'value' output param in commands without primary key
- Resolves: #1354381 ipa trust-add with raw option gives internal error.
  - trust-add: handle `--all/--raw` options properly
- Resolves: #1354493 Replica install fails with old IPA master
  - DNS install: Ensure that DNS servers container exists
- Resolves: #1354628 ipa hostgroup-add-member does not return error message
  when adding itself as member
  - frontend: copy command arguments to output params on client
- Resolves: #1355856 ipa otptoken-add --type=totp gives internal error
  - messages: specify message type for ResultFormattingError
- Resolves: #1356063 "ipa radiusproxy-add" command needs to prompt to enter
  secret key
  - expose `--secret` option in radiusproxy-* commands
  - prevent search for RADIUS proxy servers by secret
- Resolves: #1356099 Bug in the ipapwd plugin
  - Heap corruption in ipapwd plugin
- Resolves: #1356899 com.redhat.idm.trust.fetch_domains need update after thin
  client changes
  - Use server API in com.redhat.idm.trust-fetch-domains oddjob helper
- Resolves: #1356964 Renaming a user removes all of his principal aliases
  - Preserve user principal aliases during rename operation

* Fri Jul 15 2016 Petr Vobornik <pvoborni@redhat.com> - 4.4.0-2.1
- Resolves: #1274524 [RFE] Qualify up to 60 IdM replicas
- Resolves: #1320838 [RFE] Support IdM Client in a DNS domain controlled by AD
- Related: #1356134 'kinit -E' does not work for IPA user

* Thu Jul 14 2016 Petr Vobornik <pvoborni@redhat.com> - 4.4.0-2
- Resolves: #1356102 Server uninstall does not stop tracking lightweight sub-CA
  with certmonger
  - uninstall: untrack lightweight CA certs
- Resolves: #1351807 ipa-nis-manage config.get_dn missing
  - ipa-nis-manage: Use server API to retrieve plugin status
- Resolves: #1353452 ipa-compat-manage command failed,
  exception: NotImplementedError: config.get_dn()
  - ipa-compat-manage: use server API to retrieve plugin status
- Resolves: #1353899 ipa-advise: object of type 'type' has no len()
  - ipa-advise: correct handling of plugin namespace iteration
- Resolves: #1356134 'kinit -E' does not work for IPA user
  - kdb: check for local realm in enterprise principals
- Resolves: #1353072 ipa unknown command vault-add
  - Enable vault-* commands on client
  - vault-add: set the default vault type on the client side if none was given
- Resolves: #1353995 Default CA can be used without a CA ACL
  - caacl: expand plugin documentation
- Resolves: #1356144 host-find should not print SSH keys by default, only
  SSH fingerprints
  - host-find: do not show SSH key by default
- Resolves: #1353506 ipa migrate-ds command fails for IPA in RHEL 7.3
  - Removed unused method parameter from migrate-ds

* Fri Jul  1 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-1
- Resolves: #747612 [RFE] IPA should support and manage DNS sites
- Resolves: #826790 Disabling password expiration (--maxlife=0 and --minlife=0)
  in the default global_policy in IPA sets user's password expiration
  (krbPasswordExpiration) to be 90 days
- Resolves: #896699 ipa-replica-manage -H does not delete DNS SRV records
- Resolves: #1084018 [RFE] Add IdM user password change support for legacy
  client compat tree
- Resolves: #1117306 [RFE] Allow multiple Principals per host entry (Kerberos
  aliases)
  - Fix incorrect check for principal type when evaluating CA ACLs
- Resolves: #1146860 [RFE] Offer OTP generation for host enrollment in the UI
- Resolves: #1238190 ipasam unable to lookup group in directory yet manual
  search works
- Resolves: #1250110 search by users which don't have read rights for all attrs
  in search_attributes fails
- Resolves: #1263764 Show Certificate displays in useless format
- Resolves: #1272491 [WebUI] Certificate action dropdown does not display all
  the options after adding new certificate
- Resolves: #1292141 Rebase to FreeIPA 4.4+
  - Rebase to 4.4.0
- Resolves: #1294503 IPA fails to issue 3rd party certs
- Resolves: #1298242 [RFE] API compatibility - compatibility of clients
- Resolves: #1298848 [RFE] Centralized topology management
- Resolves: #1298966 [RFE] Extend Smart Card support
- Resolves: #1315146 Multiple clients cannot join domain simultaneously:
  /var/run/httpd/ipa/clientcaches race condition?
- Resolves: #1318903 ipa server install failing when SUBCA signs the cert
- Resolves: #1319003 ipa-winsync-migrate: Traceback should be fixed with proper
  console output
- Resolves: #1324055 IPA always qualify requests for admin
- Resolves: #1328552 [RFE] Allow users to authenticate with alternative names
- Resolves: #1334582 Inconsistent UI and CLI options for removing certificate
  hold
- Resolves: #1346321 Exclude o=ipaca subtree from Retro Changelog (syncrepl)
- Resolves: #1349281 Fix `Conflicts` with ipa-python
- Resolves: #1350695 execution of copy-schema script fails
- Resolves: #1351118 upgrade failed for RHEL-7.3 from RHEL-7.2.z
- Resolves: #1351153 AVC seen on Replica during ipa-server upgrade test
  execution to 7.3
- Resolves: #1351276 ipa-server-install with dns cannot resolve itself to
  create ipa-ca entry
- Related: #1343422 [RFE] Add GssapiImpersonate option

* Wed Jun 22 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-0.2.alpha1
- Resolves: #1348948 IPA server install fails with build
  ipa-server-4.4.0-0.el7.1.alpha1
  - Revert "Increased mod_wsgi socket-timeout"

* Wed Jun 22 2016 Jan Cholasta <jcholast@redhat.com> - 4.4.0-0.1.alpha1
- Resolves: #712109 "krbExtraData not allowed" is logged in DS error log while
  setting password for default sudo binddn.
- Resolves: #747612 [RFE] IPA should support and manage DNS sites
- Resolves: #768316 [RFE] ipa-getkeytab should auto-detect the ipa server name
- Resolves: #825391 [RFE] Replica installation should provide a means for
  inheriting nssldap security access settings
- Resolves: #921497 Incorrect *.py[co] files placement
- Resolves: #1029640 RHEL7 IPA to add DNA Plugin config for dnaRemote support
- Resolves: #1029905 389 DS cache sizes not replicated to IPA replicas
- Resolves: #1196958 IPA replica installation failing with high number of users
  (160000).
- Resolves: #1219402 IPA suggests to uninstall a client when the user needs to
  uninstall a replica
- Resolves: #1224057 [RFE] TGS authorization decisions in KDC based on
  Authentication Indicator
- Resolves: #1234222 [WebUI] UI error message is not appropriate for "Kerberos
  principal expiration"
- Resolves: #1234223 [WebUI] General invalid password error message appearing
  for "Locked user"
- Resolves: #1254267 ipa-server-install failure applying ldap updates with
  limits exceeded
- Resolves: #1258626 realmdomains-mod --add-domain command throwing error when
  doamin already is in forwardzone.
- Resolves: #1259020 ipa-server-adtrust-install doesn't allow
  NetBIOS-name=EXAMPLE-TEST.COM (dash character)
- Resolves: #1260993 DNSSEC signing enablement on dnszone should throw error
  message when DNSSEC master not installed
- Resolves: #1262747 dnssec options missing in ipa-dns-install man page
- Resolves: #1265900 Fail installation immediately after dirsrv fails to
  install using ipa-server-install
- Resolves: #1265915 idoverrideuser-find fails if any SID anchor is not
  resolvable anymore
- Resolves: #1268027 ipa-dnskeysync-replica crash with backtrace -
  LimitsExceeded: limits exceeded for this query
- Resolves: #1269089 Certificate of managed-by host/service fails to resubmit
- Resolves: #1269200 ipa-server crashing while trying to preserve admin user
- Resolves: #1271321 Reduce ioblocktimeout and idletimeout defaults
- Resolves: #1271579 Automember rule expressions disappear from tables on
  single expression delete
- Resolves: #1275816 Incomplete ports for IPA ad-trust
- Resolves: #1276351 [RFE] Remove
  /usr/share/ipa/updates/50-lockout-policy.update file from IPA releases
- Resolves: #1277109 Add tool tips for Revert, Refresh, Undo, and Undo All in
  the IPA UI
- Resolves: #1278426 Better error message needed for invalid ca-signing-algo
  option
- Resolves: #1279932 ipa-client-install --request-cert needs workaround in
  anaconda chroot
- Resolves: #1282521 Creating a user w/o private group fails when doing so in
  WebUI
- Resolves: #1283879 ipa-winsync-migrate: Traceback message should be replaced
  by "IPA is not configured on this system"
- Resolves: #1285071 ipa-kra-install fails on replica looking for admin cert
  file
- Resolves: #1287194 [RFE] Support of UPN for trusted domains
- Resolves: #1288967 Normalize Manager entry in ipa user-add
- Resolves: #1289487 Priority field missing in Password Policy detail tab
- Resolves: #1291140 ipa client should configure kpasswd_server directive in
  krb5.conf
- Resolves: #1292141 Rebase to FreeIPA 4.4+
  - Rebase to 4.4.0.alpha1
- Resolves: #1298848 [RFE] Centralized topology management
- Resolves: #1300576 Browser setup page includes instructions for Internet
  Explorer
- Resolves: #1301586 ipa host-del --updatedns should remove related dns
  entries.
- Resolves: #1304618 Residual Files After IPA Server Uninstall
- Resolves: #1305144 ipa-python does not require its dependencies
- Resolves: #1309700 Process /usr/sbin/winbindd was killed by signal 6
- Resolves: #1313798 Console output post ipa-winsync-migrate command should be
  corrected.
- Resolves: #1314786 [RFE] External Trust with Active Directory domain
- Resolves: #1319023 Include description for 'status' option in man page for
  ipactl command.
- Resolves: #1319912 ipa-server-install does not completely change hostname and
  named-pkcs11 fails
- Resolves: #1320891 IPA Error 3009: Validation error: Invalid 'ptrrecord':
  Reverse zone in-addr.arpa. requires exactly 4 IP address compnents, 5 given
- Resolves: #1327207 ipa cert-revoke --help doesn't provide enough info on
  revocation reasons
- Resolves: #1328549 "ipa-kra-install" command reports incorrect message when
  it is executed on server already installed with KRA.
- Resolves: #1329209 ipa-nis-manage enable: change service name from 'portmap'
  to 'rpcbind'
- Resolves: #1329275 ipa-nis-manage command should include status option
- Resolves: #1330843 'man ipa' should be updated with latest commands
- Resolves: #1333755 ipa cert-request causes internal server error while
  requesting certificate
- Resolves: #1337484 EOF is not handled for ipa-client-install command
- Resolves: #1338031 Insufficient 'write' privilege on some attributes for the
  members of the role which has "User Administrators" privilege.
- Resolves: #1343142 IPA DNS should do better verification of DNS zones
- Resolves: #1347928 Frontpage exposes runtime error with no cookies enabled in
  browser

* Wed May 25 2016 Jan Cholasta <jcholast@redhat.com> - 4.3.1-0.201605241723GIT1b427d3.1
- Resolves: #1339483 ipa-server-install fails with ERROR pkinit_cert_files
  - Fix incorrect rebase of patch 1001

* Tue May 24 2016 Jan Cholasta <jcholast@redhat.com> - 4.3.1-0.201605241723GIT1b427d3
- Resolves: #1339233 CA installed on replica is always marked as renewal master
- Related: #1292141 Rebase to FreeIPA 4.4+
  - Rebase to 4.3.1.201605241723GIT1b427d3

* Tue May 24 2016 Jan Cholasta <jcholast@redhat.com> - 4.3.1-0.201605191449GITf8edf37.1
- Resolves: #1332809 ipa-server-4.2.0-15.el7_2.6.1.x86_64 fails to install
  because of missing dependencies
  - Rebuild with krb5-1.14.1

* Fri May 20 2016 Jan Cholasta <jcholast@redhat.com> - 4.3.1-0.201605191449GITf8edf37
- Resolves: #837369 [RFE] Switch to client promotion to replica model
- Resolves: #1199516 [RFE] Move replication topology to the shared tree
- Resolves: #1206588 [RFE] Visualize FreeIPA server replication topology
- Resolves: #1211602 Hide ipa-server-install KDC master password option (-P)
- Resolves: #1212713 ipa-csreplica-manage: it could be nice to have also
  list-ruv / clean-ruv / abort-clean-ruv for o=ipaca backend
- Resolves: #1267206 ipa-server-install uninstall should warn if no
  installation found
- Resolves: #1295865 The Domain option is not correctly set in idmapd.conf when
  ipa-client-automount is executed.
- Resolves: #1327092 URI details missing and OCSP-URI details are incorrectly
  displayed when certificate generated using IPA on RHEL 7.2up2.
- Resolves: #1332809 ipa-server-4.2.0-15.el7_2.6.1.x86_64 fails to install
  because of missing dependencies
- Related: #1292141 Rebase to FreeIPA 4.4+
  - Rebase to 4.3.1.201605191449GITf8edf37

* Mon Apr 18 2016 Jan Cholasta <jcholast@redhat.com> - 4.2.0-16
- Resolves: #1277696 IPA certificate auto renewal fail with "Invalid
  Credential"
  - cert renewal: make renewal of ipaCert atomic
- Resolves: #1278330 installer options are not validated at the beginning of
  installation
  - install: fix command line option validation
- Resolves: #1282845 sshd_config change on ipa-client-install can prevent sshd
  from starting up
  - client install: do not corrupt OpenSSH config with Match sections
- Resolves: #1282935 ipa upgrade causes vault internal error
  - install: export KRA agent PEM file in ipa-kra-install
- Resolves: #1283429 Default CA ACL rule is not created during
  ipa-replica-install
  - TLS and Dogtag HTTPS request logging improvements
  - Avoid race condition caused by profile delete and recreate
  - Do not erroneously reinit NSS in Dogtag interface
  - Add profiles and default CA ACL on migration
  - disconnect ldap2 backend after adding default CA ACL profiles
  - do not disconnect when using existing connection to check default CA ACLs
- Resolves: #1283430 ipa-kra-install: fails to apply updates
  - suppress errors arising from adding existing LDAP entries during KRA
    install
- Resolves: #1283748 Caching of ipaconfig does not work in framework
  - fix caching in get_ipa_config
- Resolves: #1283943 IPA DNS Zone/DNS Forward Zone details missing after
  upgrade from RHEL 7.0 to RHEL 7.2
  - upgrade: fix migration of old dns forward zones
  - Fix upgrade of forwardzones when zone is in realmdomains
- Resolves: #1284413 ipa-cacert-manage renew fails on nonexistent ldap
  connection
  - ipa-cacert-renew: Fix connection to ldap.
- Resolves: #1284414 ipa-otptoken-import fails on nonexistent ldap connection
  - ipa-otptoken-import: Fix connection to ldap.
- Resolves: #1286635 IPA server upgrade fails from RHEL 7.0 to RHEL 7.2 using
  "yum update ipa* sssd"
  - Set minimal required version for openssl
- Resolves: #1286781 ipa-nis-manage does not update ldap with all NIS maps
  - Upgrade: Fix upgrade of NIS Server configuration
- Resolves: #1289311 umask setting causes named-pkcs11 issue with directory
  permissions on /var/lib/ipa/dnssec
  - DNS: fix file permissions
  - Explicitly call chmod on newly created directories
  - Fix: replace mkdir with chmod
- Resolves: #1290142 Broken 7.2.0 to 7.2.z upgrade - flawed version comparison
  - Fix version comparison
  - use FFI call to rpmvercmp function for version comparison
- Resolves: #1292595 In IPA-AD trust environment some secondary IPA based Posix
  groups are missing
  - ipa-kdb: map_groups() consider all results
- Resolves: #1293870 User should be notified for wrong password in password
  reset page
  - Fixed login error message box in LoginScreen page
- Resolves: #1296196 Sysrestore did not restore state if a key is specified in
  mixed case
  - Allow to used mixed case for sysrestore
- Resolves: #1296214 DNSSEC key purging is not handled properly
  - DNSSEC: Improve error reporting from ipa-ods-exporter
  - DNSSEC: Make sure that current state in OpenDNSSEC matches key state in
    LDAP
  - DNSSEC: Make sure that current key state in LDAP matches key state in BIND
  - DNSSEC: remove obsolete TODO note
  - DNSSEC: add debug mode to ldapkeydb.py
  - DNSSEC: logging improvements in ipa-ods-exporter
  - DNSSEC: remove keys purged by OpenDNSSEC from master HSM from LDAP
  - DNSSEC: ipa-dnskeysyncd: Skip zones with old DNSSEC metadata in LDAP
  - DNSSEC: ipa-ods-exporter: add ldap-cleanup command
  - DNSSEC: ipa-dnskeysyncd: call ods-signer ldap-cleanup on zone removal
  - DNSSEC: Log debug messages at log level DEBUG
- Resolves: #1296216 ipa-server-upgrade fails if certmonger is not running
  - prevent crash of CA-less server upgrade due to absent certmonger
  - always start certmonger during IPA server configuration upgrade
- Resolves: #1297811 The ipa -e skip_version_check=1 still issues
  incompatibility error when called against RHEL 6 server
  - ipalib: assume version 2.0 when skip_version_check is enabled
- Resolves: #1298289 install fails when locale is "fr_FR.UTF-8"
  - Do not decode HTTP reason phrase from Dogtag
- Resolves: #1300252 shared certificateProfiles container is missing on a
  freshly installed RHEL7.2 system
  - upgrade: unconditional import of certificate profiles into LDAP
- Resolves: #1301674 --setup-dns and other options is forgotten for using an
  external PKI
  - installer: Propagate option values from components instead of copying them.
  - installer: Fix logic of reading option values from cache.
- Resolves: #1301687 issues with migration from RHEL 6 self-signed to RHEL 7 CA
  IPA setup
  - ipa-ca-install: print more specific errors when CA is already installed
  - cert renewal: import all external CA certs on IPA CA cert renewal
  - CA install: explicitly set dogtag_version to 10
  - fix standalone installation of externally signed CA on IPA master
  - replica install: validate DS and HTTP server certificates
  - replica install: improvements in the handling of CA-related IPA config
    entries
- Resolves: #1301901 [RFE] compat tree: show AD members of IPA groups
  - slapi-nis: update configuration to allow external members of IPA groups
- Resolves: #1305533 ipa trust-add succeded but after that ipa trust-find
  returns "0 trusts matched"
  - upgrade: fix config of sidgen and extdom plugins
  - trusts: use ipaNTTrustPartner attribute to detect trust entries
  - Warn user if trust is broken
  - fix upgrade: wait for proper DS socket after DS restart
  - Insure the admin_conn is disconnected on stop
  - Fix connections to DS during installation
  - Fix broken trust warnings
- Resolves: #1321092 Installers fail when there are multiple versions of the
  same certificate
  - certdb: never use the -r option of certutil
- Related: #1317381 Crash during IPA upgrade due to slapd
  - spec file: update minimum required version of slapi-nis
- Related: #1322691 CVE-2015-5370 CVE-2016-2110 CVE-2016-2111 CVE-2016-2112
  CVE-2016-2113 CVE-2016-2114 CVE-2016-2115 CVE-2016-2118 samba: various flaws
  [rhel-7.3]
  - Rebuild against newer Samba version

* Tue Oct 13 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-15
- Resolves: #1252556 Missing CLI param and ACL for vault service operations
  - vault: fix private service vault creation

* Mon Oct 12 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-14
- Resolves: #1262996 ipa vault internal error on replica without KRA
  - upgrade: make sure ldap2 is connected in export_kra_agent_pem
- Resolves: #1270608 IPA upgrade fails for server with CA cert signed by
  external CA
  - schema: do not derive ipaVaultPublicKey from ipaPublicKey

* Thu Oct  8 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-13
- Resolves: #1217009 OTP sync in UI does not work for TOTP tokens
  - Fix an integer underflow bug in libotp
- Resolves: #1262996 ipa vault internal error on replica without KRA
  - install: always export KRA agent PEM file
  - vault: select a server with KRA for vault operations
- Resolves: #1269777 IPA restore overwrites /etc/passwd and /etc/group files
  - do not overwrite files with local users/groups when restoring authconfig
- Renamed patch 1011 to 0138, as it was merged upstream

* Wed Sep 23 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-12
- Resolves: #1204205 [RFE] ID Views: Automated migration tool from Winsync to
  Trusts
  - winsync-migrate: Convert entity names to posix friendly strings
  - winsync-migrate: Properly handle collisions in the names of external groups
- Resolves: #1261074 Adjust Firefox configuration to new extension signing
  policy
  - webui: use manual Firefox configuration for Firefox >= 40
- Resolves: #1263337 IPA Restore failed with installed KRA
  - ipa-backup: Add mechanism to store empty directory structure
- Resolves: #1264793 CVE-2015-5284 ipa: ipa-kra-install includes certificate
  and private key in world readable file [rhel-7.2]
  - install: fix KRA agent PEM file permissions
- Resolves: #1265086 Mark IdM API Browser as experimental
  - WebUI: add API browser is experimental warning
- Resolves: #1265277 Fix kdcproxy user creation
  - install: create kdcproxy user during server install
  - platform: add option to create home directory when adding user
  - install: fix kdcproxy user home directory
- Resolves: #1265559 GSS failure after ipa-restore
  - destroy httpd ccache after stopping the service

* Thu Sep 17 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-11
- Resolves: #1258965 ipa vault: set owner of vault container
  - baseldap: make subtree deletion optional in LDAPDelete
  - vault: add vault container commands
  - vault: set owner to current user on container creation
  - vault: update access control
  - vault: add permissions and administrator privilege
  - install: support KRA update
- Resolves: #1261586 ipa config-mod addattr fails for ipauserobjectclasses
  - config: allow user/host attributes with tagging options
- Resolves: #1262315 Unable to establish winsync replication
  - winsync: Add inetUser objectclass to the passsync sysaccount

* Wed Sep 16 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-10
- Resolves: #1260663 crash of ipa-dnskeysync-replica component during
  ipa-restore
  - IPA Restore: allows to specify files that should be removed
- Resolves: #1261806 Installing ipa-server package breaks httpd
  - Handle timeout error in ipa-httpd-kdcproxy
- Resolves: #1262322 Failed to backup CS.cfg message in upgrade.
  - Server Upgrade: backup CS.cfg when dogtag is turned off

* Wed Sep  9 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-9
- Resolves: #1257074 The KRA agent cert is stored in a PEM file that is not
  tracked
  - cert renewal: Include KRA users in Dogtag LDAP update
  - cert renewal: Automatically update KRA agent PEM file
- Resolves: #1257163 renaming certificatte profile with --rename option leads
  to integrity issues
  - certprofile: remove 'rename' option
- Resolves: #1257968 kinit stop working after ipa-restore
  - Backup: back up the hosts file
- Resolves: #1258926 Remove 'DNSSEC is experimental' warnings
  - DNSSEC: remove "DNSSEC is experimental" warnings
- Resolves: #1258929 Uninstallation of IPA leaves extra entry in /etc/hosts
  - Installer: do not modify /etc/hosts before user agreement
- Resolves: #1258944 DNSSEC daemons may deadlock when processing more than 1
  zone
  - DNSSEC: backup and restore opendnssec zone list file
  - DNSSEC: remove ccache and keytab of ipa-ods-exporter
  - DNSSEC: prevent ipa-ods-exporter from looping after service auto-restart
  - DNSSEC: Fix deadlock in ipa-ods-exporter <-> ods-enforcerd interaction
  - DNSSEC: Fix HSM synchronization in ipa-dnskeysyncd when running on DNSSEC
    key master
  - DNSSEC: Fix key metadata export
  - DNSSEC: Wrap master key using RSA OAEP instead of old PKCS v1.5.
- Resolves: #1258964 revert to use ldapi to add kra agent in KRA install
  - Using LDAPI to setup CA and KRA agents.
- Resolves: #1259848 server closes connection and refuses commands after
  deleting user that is still logged in
  - ldap: Make ldap2 connection management thread-safe again
- Resolves: #1259996 AttributeError: 'NameSpace' object has no attribute
  'ra_certprofile' while ipa-ca-install
  - load RA backend plugins during standalone CA install on CA-less IPA master

* Wed Aug 26 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-8
- Resolves: #1254689 Storing big file as a secret in vault raises traceback
  - vault: Limit size of data stored in vault
- Resolves: #1255880 ipactl status should distinguish between different
  pki-tomcat services
  - ipactl: Do not start/stop/restart single service multiple times

* Wed Aug 26 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-7
- Resolves: #1256840 [webui] majority of required fields is no longer marked as
  required
  - fix missing information in object metadata
- Resolves: #1256842 [webui] no option to choose trust type when creating a
  trust
  - webui: add option to establish bidirectional trust
- Resolves: #1256853 Clear text passwords in KRA install log
  - Removed clear text passwords from KRA install log.
- Resolves: #1257072 The "Standard Vault" MUST not be the default and must be
  discouraged
  - vault: change default vault type to symmetric
- Resolves: #1257163 renaming certificatte profile with --rename option leads
  to integrity issues
  - certprofile: prevent rename (modrdn)

* Wed Aug 26 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-6
- Resolves: #1249226 IPA dnssec-validation not working for AD dnsforwardzone
  - DNSSEC: fix forward zone forwarders checks
- Resolves: #1250190 idrange is not added for sub domain
  - trusts: format Kerberos principal properly when fetching trust topology
- Resolves: #1252334 User life cycle: missing ability to provision a stage user
  from a preserved user
  - Add user-stage command
- Resolves: #1252863 After applying RHBA-2015-1554 errata, IPA service fails to
  start.
  - spec file: Add Requires(post) on selinux-policy
- Resolves: #1254304 Changing vault encryption attributes
  - Change internal rsa_(public|private)_key variable names
  - Added support for changing vault encryption.
- Resolves: #1256715 Executing user-del --preserve twice removes the user
  pernamently
  - improve the usability of `ipa user-del --preserve` command

* Wed Aug 19 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-5
- Resolves: #1199530 [RFE] Provide user lifecycle managment capabilities
  - user-undel: Fix error messages.
- Resolves: #1200694 [RFE] Support for multiple cert profiles
  - Prohibit deletion of predefined profiles
- Resolves: #1232819 testing ipa-restore on fresh system install fails
  - Backup/resore authentication control configuration
- Resolves: #1243331 pkispawn fails when migrating to 4.2 server from 3.0
  server
  - Require Dogtag PKI >= 10.2.6
- Resolves: #1245225 Asymmetric vault drops traceback when the key is not
  proper
  - Asymmetric vault: validate public key in client
- Resolves: #1248399 Missing DNSSEC related files in backup
  - fix typo in BasePathNamespace member pointing to ods exporter config
  - ipa-backup: archive DNSSEC zone file and kasp.db
- Resolves: #1248405 PassSync should be disabled after ipa-winsync-migrate is
  finished
  - winsync-migrate: Add warning about passsync
  - winsync-migrate: Expand the man page
- Resolves: #1248524 User can't find any hosts using "ipa host-find $HOSTNAME"
  - adjust search so that it works for non-admin users
- Resolves: #1250093 ipa certprofile-import accepts invalid config
  - Require Dogtag PKI >= 10.2.6
- Resolves: #1250107 IPA framework should not allow modifying trust on AD trust
  agents
  - trusts: Detect missing Samba instance
- Resolves: #1250111 User lifecycle - preserved users can be assigned
  membership
  - ULC: Prevent preserved users from being assigned membership
- Resolves: #1250145 Add permission for user to bypass caacl enforcement
  - Add permission for bypassing CA ACL enforcement
- Resolves: #1250190 idrange is not added for sub domain
  - idranges: raise an error when local IPA ID range is being modified
  - trusts: harden trust-fetch-domains oddjobd-based script
- Resolves: #1250928 Man page for ipa-server-install is out of sync
  - install: Fix server and replica install options
- Resolves: #1251225 IPA default CAACL does not allow cert-request for services
  after upgrade
  - Fix default CA ACL added during upgrade
- Resolves: #1251561 ipa vault-add Unknown option: ipavaultpublickey
  - validate mutually exclusive options in vault-add
- Resolves: #1251579 ipa vault-add --user should set container owner equal to
  user on first run
  - Fixed vault container ownership.
- Resolves: #1252517 cert-request rejects request with correct
  krb5PrincipalName SAN
  - Fix KRB5PrincipalName / UPN SAN comparison
- Resolves: #1252555 ipa vault-find doesn't work for services
  - vault: Add container information to vault command results
  - Add flag to list all service and user vaults
- Resolves: #1252556 Missing CLI param and ACL for vault service operations
  - Added CLI param and ACL for vault service operations.
- Resolves: #1252557 certprofile: improve profile format documentation
  - certprofile-import: improve profile format documentation
  - certprofile: add profile format explanation
- Resolves: #1253443 ipa vault-add creates vault with invalid type
  - vault: validate vault type
- Resolves: #1253480 ipa vault-add-owner does not fail when adding an existing
  owner
  - baseldap: Allow overriding member param label in LDAPModMember
  - vault: Fix param labels in output of vault owner commands
- Resolves: #1253511 ipa vault-find does not use criteria
  - vault: Fix vault-find with criteria
- Resolves: #1254038 ipa-replica-install pk12util error returns exit status 10
  - install: Fix replica install with custom certificates
- Resolves: #1254262 ipa-dnskeysync-replica crash cannot contact kdc
  - improve the handling of krb5-related errors in dnssec daemons
- Resolves: #1254412 when dirsrv is off ,upgrade from 7.1 to 7.2 fails with
  starting CA and named-pkcs11.service
  - Server Upgrade: Start DS before CA is started.
- Resolves: #1254637 Add ACI and permission for managing user userCertificate
  attribute
  - add permission: System: Manage User Certificates
- Resolves: #1254641 Remove CSR allowed-extensions restriction
  - cert-request: remove allowed extensions check
- Resolves: #1254693 vault --service does not normalize service principal
  - vault: normalize service principal in service vault operations
- Resolves: #1254785 ipa-client-install does not properly handle dual stacked
  hosts
  - client: Add support for multiple IP addresses during installation.
  - Add dependency to SSSD 1.13.1
  - client: Add description of --ip-address and --all-ip-addresses to man page

* Tue Aug 11 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-4
- Resolves: #1072383 [RFE] Provide ability to map CAC identity certificates to
  users in IdM
  - store certificates issued for user entries as
  - user-show: add --out option to save certificates to file
- Resolves: #1145748 [RFE] IPA running with One Way Trust
  - Fix upgrade of sidgen and extdom plugins
- Resolves: #1195339 ipa-client-install changes the label on various files
  which causes SELinux denials
  - Use 'mv -Z' in specfile to restore SELinux context
- Resolves: #1198796 Text in UI should describe differing LDAP vs Krb behavior
  for combinations of "User authentication types"
  - webui: add LDAP vs Kerberos behavior description to user auth
- Resolves: #1199530 [RFE] Provide user lifecycle managment capabilities
  - ULC: Fix stageused-add --from-delete command
- Resolves: #1200694 [RFE] Support for multiple cert profiles
  - certprofile-import: do not require profileId in profile data
  - Give more info on virtual command access denial
  - Allow SAN extension for cert-request self-service
  - Add profile for DNP3 / IEC 62351-8 certificates
  - Work around python-nss bug on unrecognised OIDs
- Resolves: #1204501 [RFE] Add Password Vault (KRA) functionality
  - Validate vault's file parameters
  - Fixed missing KRA agent cert on replica.
- Resolves: #1225866 display browser config options that apply to the browser.
  - webui: add Kerberos configuration instructions for Chrome
  - Remove ico files from Makefile
- Resolves: #1246342 Unapply idview raises internal error
  - idviews: Check for the Default Trust View only if applying the view
- Resolves: #1248102 [webui] regression - incorrect/no failed auth messages
  - webui: fix regressions failed auth messages
- Resolves: #1248396 Internal error in DomainValidator.__search_in_dc
  - dcerpc: Fix UnboundLocalError for ccache_name
- Resolves: #1249455 ipa trust-add failed CIFS server configuration does not
  allow access to \\pipe\lsarpc
  - Fix selector of protocol for LSA RPC binding string
  - dcerpc: Simplify generation of LSA-RPC binding strings
- Resolves: #1250192 Error in ipa trust-fecth-domains
  - Fix incorrect type comparison in trust-fetch-domains
- Resolves: #1251553 Winsync setup fails with unexpected error
  - replication: Fix incorrect exception invocation
- Resolves: #1251854 ipa aci plugin is not parsing aci's correctly.
  - ACI plugin: correctly parse bind rules enclosed in
- Resolves: #1252414 Trust agent install does not detect available replicas to
  add to master
  - adtrust-install: Correctly determine 4.2 FreeIPA servers

* Fri Jul 24 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-3
- Resolves: #1170770 [AD TRUST]IPA should detect inconsistent realm domains
  that conflicts with AD DC
  - trusts: Check for AD root domain among our trusted domains
- Resolves: #1195339 ipa-client-install changes the label on various files
  which causes SELinux denials
  - sysrestore: copy files instead of moving them to avoind SELinux issues
- Resolves: #1196656 [ipa-client][rhel71] enable debugging for spawned
  commands / ntpd -qgc $tmpfile hangs
  - enable debugging of ntpd during client installation
- Resolves: #1205264 Migration UI Does Not Work When Anonymous Bind is Disabled
  - migration: Use api.env variables.
- Resolves: #1212719 abort-clean-ruv subcommand should allow
  replica-certifyall: no
  - Allow value 'no' for replica-certify-all attr in abort-clean-ruv subcommand
- Resolves: #1216935 ipa trust-add shows ipa: ERROR: an internal error has
  occurred
  - dcerpc: Expand explanation for WERR_ACCESS_DENIED
  - dcerpc: Fix UnboundLocalError for ccache_name
- Resolves: #1222778 idoverride group-del can delete user and user-del can
  delete group
  - dcerpc: Add get_trusted_domain_object_type method
  - idviews: Restrict anchor to name and name to anchor conversions
  - idviews: Enforce objectclass check in idoverride*-del
- Resolves: #1234919 Be able to request certificates without certmonger service
  running
  - cermonger: Use private unix socket when DBus SystemBus is not available.
  - ipa-client-install: Do not (re)start certmonger and DBus daemons.
- Resolves: #1240939 Please add dependency on bind-pkcs11
  - Create server-dns sub-package.
  - ipaplatform: Add constants submodule
  - DNS: check if DNS package is installed
- Resolves: #1242914 Bump minimal selinux-policy and add booleans to allow
  calling out oddjobd-activated services
  - selinux: enable httpd_run_ipa to allow communicating with oddjobd services
- Resolves: #1243261 non-admin users cannot search hbac rules
  - fix hbac rule search for non-admin users
  - fix selinuxusermap search for non-admin users
- Resolves: #1243652 Client has missing dependency on memcache
  - do not import memcache on client
- Resolves: #1243835 [webui] user change password dialog does not work
  - webui: fix user reset password dialog
- Resolves: #1244802 spec: selinux denial during kdcproxy user creation
  - Fix selinux denial during kdcproxy user creation
- Resolves: #1246132 trust-fetch-domains: Do not chown keytab to the sssd user
  - oddjob: avoid chown keytab to sssd if sssd user does not exist
- Resolves: #1246136 Adding a privilege to a permission avoids validation
  - Validate adding privilege to a permission
- Resolves: #1246141 DNS Administrators cannot search in zones
  - DNS: Consolidate DNS RR types in API and schema
- Resolves: #1246143 User plugin - user-find doesn't work properly with manager
  option
  - fix broken search for users by their manager

* Wed Jul 15 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-2
- Resolves: #1131907 [ipa-client-install] cannot write certificate file
  '/etc/ipa/ca.crt.new': must be string or buffer, not None
- Resolves: #1195775 unsaved changes dialog internally inconsistent
- Resolves: #1199530 [RFE] Provide user lifecycle managment capabilities
  - Stageusedr-activate: show username instead of DN
- Resolves: #1200694 [RFE] Support for multiple cert profiles
  - Prevent to rename certprofile profile id
- Resolves: #1222047 IPA to AD Trust: IPA ERROR 4016: Remote Retrieve Error
- Resolves: #1224769 copy-schema-to-ca.py does not overwrites schema files
  - copy-schema-to-ca: allow to overwrite schema files
- Resolves: #1241941 kdc component installation of IPA failed
  - spec file: Update minimum required version of krb5
- Resolves: #1242036 Replica install fails to update DNS records
  - Fix DNS records installation for replicas
- Resolves: #1242884 Upgrade to 4.2.0 fails when enabling kdc proxy
  - Start dirsrv for kdcproxy upgrade

* Thu Jul  9 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-1
- Resolves: #846033  [RFE] Documentation for JSONRPC IPA API
- Resolves: #989091  Ability to manage IdM/IPA directly from a standard LDAP
  client
- Resolves: #1072383 [RFE] Provide ability to map CAC identity certificates to
  users in IdM
- Resolves: #1115294 [RFE] Add support for DNSSEC
- Resolves: #1145748 [RFE] IPA running with One Way Trust
- Resolves: #1199520 [RFE] Introduce single upgrade tool - ipa-server-upgrade
- Resolves: #1199530 [RFE] Provide user lifecycle managment capabilities
- Resolves: #1200694 [RFE] Support for multiple cert profiles
- Resolves: #1200728 [RFE] Replicate PKI Profile information
- Resolves: #1200735 [RFE] Allow issuing certificates for user accounts
- Resolves: #1204054 SSSD database is not cleared between installs and
  uninstalls of ipa
- Resolves: #1204205 [RFE] ID Views: Automated migration tool from Winsync to
  Trusts
- Resolves: #1204501 [RFE] Add Password Vault (KRA) functionality
- Resolves: #1204504 [RFE] Add access control so hosts can create their own
  services
- Resolves: #1206534 [RFE] Offer Kerberos over HTTP (kdcproxy) by default
- Resolves: #1206613 [RFE] Configure IPA to be a trust agent by default
- Resolves: #1209476 package ipa-client does not require package dbus-python
- Resolves: #1211589 [RFE] Add option to skip the verify_client_version
- Resolves: #1211608 [RFE] Generic support for unknown DNS RR types (RFC 3597)
- Resolves: #1215735 ipa-replica-prepare automatically adds a DNS zone
- Resolves: #1217010 OTP Manager field is not exposed in the UI
- Resolves: #1222475 krb5kdc : segfault at 0 ip 00007fa9f64d82bb sp
  00007fffd68b2340 error 6 in libc-2.17.so
- Related:  #1204809 Rebase ipa to 4.2
  - Update to upstream 4.2.0
  - Move /etc/ipa/kdcproxy to the server subpackage

* Tue Jun 23 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-0.2.alpha1
- Resolves: #1228671 pkispawn fails in ipa-ca-install and ipa-kra-install
- Related:  #1204809 Rebase ipa to 4.2
  - Fix minimum version of slapi-nis
  - Require python-sss and python-sss-murmur (provided by sssd-1.13.0)

* Mon Jun 22 2015 Jan Cholasta <jcholast@redhat.com> - 4.2.0-0.1.alpha1
- Resolves: #805188  [RFE] "ipa migrate-ds" ldapsearches with scope=1
- Resolves: #1019272 With 20000+ users, adding a user to a group intermittently
  throws Internal server error
- Resolves: #1035494 Unable to add Kerberos principal via kadmin.local
- Resolves: #1045153 ipa-managed-entries --list -p <badpassword> still requires
  DM password
- Resolves: #1125950 ipa-server-install --uinstall doesn't remove port 7389
  from ldap_port_t
- Resolves: #1132540 [RFE] Expose service delegation rules in UI and CLI
- Resolves: #1145584 ipaserver/install/cainstance.py creates pkiuser not
  matching uidgid
- Resolves: #1176036 IDM client registration failure in a high load environment
- Resolves: #1183116 Remove Requires: subscription-manager
- Resolves: #1186054 permission-add does not prompt to enter --right option in
  interactive mode
- Resolves: #1187524 Replication agreement with replica not disabled when
  ipa-restore done without IPA installed
- Resolves: #1188195 Fax number not displayed for user-show when kinit'ed as
  normal user.
- Resolves: #1189034 "an internal error has occurred" during ipa host-del
  --updatedns
- Resolves: #1193554 ipa-client-automount: failing with error LDAP server
  returned UNWILLING_TO_PERFORM. This likely means that minssf is enabled.
- Resolves: #1193759 IPA extdom plugin fails when encountering large groups
- Resolves: #1194312 [ipa-python] ipalib.errors.LDAPError: failed to decode
  certificate: (SEC_ERROR_INVALID_ARGS) security library: invalid arguments.
- Resolves: #1194633 Default trust view can be deleted in lower case
- Resolves: #1196455 ipa-server-install step [8/27]: starting certificate
  server instance - confusing CA staus message on TLS error
- Resolves: #1198263 Limit deadlocks between DS plugin DNA and slapi-nis
- Resolves: #1199527 [RFE] Use datepicker component for datetime fields
- Resolves: #1200867 [RFE] Make OTP validation window configurable
- Resolves: #1200883 [RFE] Switch apache to use mod_auth_gssapi
- Resolves: #1202998 CVE-2015-1827 ipa: memory corruption when using
  get_user_grouplist() [rhel-7.2]
- Resolves: #1204637 slow group operations
- Resolves: #1204642 migrate-ds: slow add o users to default group
- Resolves: #1208461 IPA CA master server update stuck on checking getStatus
  via https
- Resolves: #1211602 Hide ipa-server-install KDC master password option (-P)
- Resolves: #1211708 ipa-client-install gets stuck during NTP sync
- Resolves: #1215197 ipa-client-install ignores --ntp-server option during time
  sync
- Resolves: #1215200 ipa-client-install configures IPA server as NTP source
  even if IPA server has not ntpd configured
- Resolves: #1217009 OTP sync in UI does not work for TOTP tokens
- Related:  #1204809 Rebase ipa to 4.2
  - Update to upstream 4.2.0.alpha1

* Thu Mar 19 2015 Jan Cholasta <jcholast@redhat.com> - 4.1.0-18.3
- [ipa-python] ipalib.errors.LDAPError: failed to decode certificate:
  (SEC_ERROR_INVALID_ARGS) security library: invalid arguments. (#1194312)

* Wed Mar 18 2015 Alexander Bokovoy <abokovoy@redhat.com> - 4.1.0-18.2
- IPA extdom plugin fails when encountering large groups (#1193759)
- CVE-2015-0283 ipa: slapi-nis: infinite loop in getgrnam_r() and getgrgid_r()
  (#1202998)

* Thu Mar  5 2015 Jan Cholasta <jcholast@redhat.com> - 4.1.0-18.1
- "an internal error has occurred" during ipa host-del --updatedns (#1198431)
- Renamed patch 1013 to 0114, as it was merged upstream
- Fax number not displayed for user-show when kinit'ed as normal user.
  (#1198430)
- Replication agreement with replica not disabled when ipa-restore done without
  IPA installed (#1199060)
- Limit deadlocks between DS plugin DNA and slapi-nis (#1199128)

* Thu Jan 29 2015 Martin Kosek <mkosek@redhat.com> - 4.1.0-18
- Fix ipa-pwd-extop global configuration caching (#1187342)
- group-detach does not add correct objectclasses (#1187540)

* Tue Jan 27 2015 Jan Cholasta <jcholast@redhat.com> - 4.1.0-17
- Wrong directories created on full restore (#1186398)
- ipa-restore crashes if replica is unreachable (#1186396)
- idoverrideuser-add option --sshpubkey does not work (#1185410)

* Wed Jan 21 2015 Jan Cholasta <jcholast@redhat.com> - 4.1.0-16
- PassSync does not sync passwords due to missing ACIs (#1181093)
- ipa-replica-manage list does not list synced domain (#1181010)
- Do not assume certmonger is running in httpinstance (#1181767)
- ipa-replica-manage disconnect fails without password (#1183279)
- Put LDIF files to their original location in ipa-restore (#1175277)
- DUA profile not available anonymously (#1184149)
- IPA replica missing data after master upgraded (#1176995)

* Wed Jan 14 2015 Jan Cholasta <jcholast@redhat.com> - 4.1.0-15
- Re-add accidentally removed patches for #1170695 and #1164896

* Wed Jan 14 2015 Jan Cholasta <jcholast@redhat.com> - 4.1.0-14
- IPA Replicate creation fails with error "Update failed! Status: [10 Total
  update abortedLDAP error: Referral]" (#1166265)
- running ipa-server-install --setup-dns results in a crash (#1072502)
- DNS zones are not migrated into forward zones if 4.0+ replica is added
  (#1175384)
- gid is overridden by uid in default trust view (#1168904)
- When migrating warn user if compat is enabled (#1177133)
- Clean up debug log for trust-add (#1168376)
- No error message thrown on restore(full kind) on replica from full backup
  taken on master (#1175287)
- ipa-restore proceed even IPA not configured (#1175326)
- Data replication not working as expected after data restore from full backup
  (#1175277)
- IPA externally signed CA cert expiration warning missing from log (#1178128)
- ipa-upgradeconfig fails in CA-less installs (#1181767)
- IPA certs fail to autorenew simultaneouly (#1173207)
- More validation required on ipa-restore's options (#1176034)

* Wed Dec 17 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-13
- Expand the token auth/sync windows (#919228)
- Access is not rejected for disabled domain (#1172598)
- krb5kdc crash in ldap_pvt_search (#1170695)
- RHEL7.1 IPA server httpd avc denials after upgrade (#1164896)

* Wed Dec 10 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-12
- RHEL7.1 ipa-cacert-manage renewed certificate from MS ADCS not compatible
  (#1169591)
- CLI doesn't show SSHFP records with SHA256 added via nsupdate (regression)
  (#1172578)

* Tue Dec  9 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-11
- Throw zonemgr error message before installation proceeds (#1163849)
- Winsync: Setup is broken due to incorrect import of certificate (#1169867)
- Enable last token deletion when password auth type is configured (#919228)
- ipa-otp-lasttoken loads all user's tokens on every mod/del (#1166641)
- add --hosts and --hostgroup options to allow/retrieve keytab methods
  (#1007367)
- Extend host-show to add the view attribute in set of default attributes
  (#1168916)
- Prefer TCP connections to UDP in krb5 clients (#919228)
- [WebUI] Not able to unprovisioning service in IPA 4.1 (#1168214)
- webui: increase notification duration (#1171089)
- RHEL7.1 ipa automatic CA cert renewal stuck in submitting state (#1166931)
- RHEL7.1 ipa-cacert-manage cannot change external to self-signed ca cert
  (#1170003)
- Improve validation of --instance and --backend options in ipa-restore
  (#951581)
- RHEL7.1 ipa replica unable to replicate to rhel6 master (#1167964)
- Disable TLS 1.2 in nss.conf until mod_nss supports it (#1156466)

* Wed Nov 26 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-10
- Use NSS protocol range API to set available TLS protocols (#1156466)

* Tue Nov 25 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-9
- schema update on RHEL-6.6 using latest copy-schema-to-ca.py from RHEL-7.1
  build fails (#1167196)
- Investigate & fix Coverity defects in IPA DS/KDC plugins (#1160756)
- "ipa trust-add ... " cmd says : (Trust status: Established and verified)
  while in the logs we see "WERR_ACCESS_DENIED" during verification step.
  (#1144121)
- POODLE: force using safe ciphers (non-SSLv3) in IPA client and server
  (#1156466)
- Add support/hooks for a one-time password system like SecureID in IPA
  (#919228)
- Tracebacks with latest build for --zonemgr cli option (#1167270)
- ID Views: Support migration from the sync solution to the trust solution
  (#891984)

* Mon Nov 24 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-8
- Improve otptoken help messages (#919228)
- Ensure users exist when assigning tokens to them (#919228)
- Enable QR code display by default in otptoken-add (#919228)
- Show warning instead of error if CA did not start (#1158410)
- CVE-2014-7850 freeipa: XSS flaw can be used to escalate privileges (#1165774)
- Traceback when adding zone with long name (#1164859)
- Backup & Restore mechanism (#951581)
- ignoring user attributes in migrate-ds does not work if uppercase characters
  are returned by ldap (#1159816)
- Allow ipa-getkeytab to optionally fetch existing keys (#1007367)
- Failure when installing on dual stacked system with external ca (#1128380)
- ipa-server should keep backup of CS.cfg (#1059135)
- Tracebacks with latest build for --zonemgr cli option (#1167270)
- webui: use domain name instead of domain SID in idrange adder dialog
  (#891984)
- webui: normalize idview tab labels (#891984)

* Wed Nov 19 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-7
- ipa-csreplica-manage connect fails (#1157735)
- error message which is not understandable when IDNA2003 characters are
  present in --zonemgr (#1163849)
- Fix warning message should not contain CLI commands (#1114013)
- Renewing the CA signing certificate does not extend its validity period end
  (#1163498)
- RHEL7.1 ipa-server-install --uninstall Could not set SELinux booleans for
  httpd (#1159330)

* Thu Nov 13 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-6
- Fix: DNS installer adds invalid zonemgr email (#1056202)
- ipaplatform: Use the dirsrv service, not target (#951581)
- Fix: DNS policy upgrade raises asertion error (#1161128)
- Fix upgrade referint plugin (#1161128)
- Upgrade: fix trusts objectclass violationi (#1161128)
- group-add doesn't accept gid parameter (#1149124)

* Tue Nov 11 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-5
- Update slapi-nis dependency to pull 0.54-2 (#891984)
- ipa-restore: Don't crash if AD trust is not installed (#951581)
- Prohibit setting --rid-base for ranges of ipa-trust-ad-posix type (#1138791)
- Trust setting not restored for CA cert with ipa-restore command (#1159011)
- ipa-server-install fails when restarting named (#1162340)

* Thu Nov 06 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-4
- Update Requires on pki-ca to 10.1.2-4 (#1129558)
- build: increase java stack size for all arches
- Add ipaSshPubkey and gidNumber to the ACI to read ID user overrides (#891984)
- Fix dns zonemgr validation regression (#1056202)
- Handle profile changes in dogtag-ipa-ca-renew-agent (#886645)
- Do not wait for new CA certificate to appear in LDAP in ipa-certupdate
  (#886645)
- Add bind-dyndb-ldap working dir to IPA specfile
- Fail if certmonger can't see new CA certificate in LDAP in ipa-cacert-manage
  (#886645)
- Investigate & fix Coverity defects in IPA DS/KDC plugins (#1160756)
- Deadlock in schema compat plugin (#1161131)
- ipactl stop should stop dirsrv last (#1161129)
- Upgrade 3.3.5 to 4.1 failed (#1161128)
- CVE-2014-7828 freeipa: password not required when OTP in use (#1160877)

* Wed Oct 22 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-3
- Do not check if port 8443 is available in step 2 of external CA install
  (#1129481)

* Wed Oct 22 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-2
- Update Requires on selinux-policy to 3.13.1-4

* Tue Oct 21 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-1
- Update to upstream 4.1.0 (#1109726)

* Mon Sep 29 2014 Jan Cholasta <jcholast@redhat.com> - 4.1.0-0.1.alpha1
- Update to upstream 4.1.0 Alpha 1 (#1109726)

* Fri Sep 26 2014 Petr Vobornik <pvoborni@redhat.com> - 4.0.3-3
- Add redhat-access-plugin-ipa dependency

* Thu Sep 25 2014 Jan Cholasta <jcholast@redhat.com> - 4.0.3-2
- Re-enable otptoken_yubikey plugin

* Mon Sep 15 2014 Jan Cholasta <jcholast@redhat.com> - 4.0.3-1
- Update to upstream 4.0.3 (#1109726)

* Thu Aug 14 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-29
- Server installation fails using external signed certificates with
  "IndexError: list index out of range" (#1111320)
- Add rhino to BuildRequires to fix Web UI build error

* Tue Apr  1 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-28
- ipa-client-automount fails with incompatibility error when installed against
  older IPA server (#1083108)

* Wed Mar 26 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-27
- Proxy PKI URI /ca/ee/ca/profileSubmit to enable replication with future
  PKI versions (#1080865)

* Tue Mar 25 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-26
- When IdM server trusts multiple AD forests, IPA client returns invalid group
  membership info (#1079498)

* Thu Mar 13 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-25
- Deletion of active subdomain range should not be allowed (#1075615)

* Thu Mar 13 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-24
- PKI database is ugraded during replica installation (#1075118)

* Wed Mar 12 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-23
- Unable to add trust successfully with --trust-secret (#1075704)

* Wed Mar 12 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-22
- ipa-replica-install never checks for 7389 port (#1075165)
- Non-terminated string may be passed to LDAP search (#1075091)
- ipa-sam may fail to translate group SID into GID (#1073829)
- Excessive LDAP calls by ipa-sam during Samba FS operations (#1075132)

* Thu Mar  6 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-21
- Do not fetch a principal two times, remove potential memory leak (#1070924)

* Wed Mar  5 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-20
- trustdomain-find with pkey-only fails (#1068611)
- Invalid credential cache in trust-add (#1069182)
- ipa-replica-install prints unexpected error (#1069722)
- Too big font in input fields in details facet in Firefox (#1069720)
- trust-add for POSIX AD does not fetch trustdomains (#1070925)
- Misleading trust-add error message in some cases (#1070926)
- Access is not rejected for disabled domain (#1070924)

* Wed Feb 26 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-19
- Remove ipa-backup and ipa-restore functionality from RHEL (#1003933)

* Wed Feb 12 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-18
- Display server name in ipa command's verbose mode (#1061703)
- Remove sourcehostcategory from default HBAC rule (#1061187)
- dnszone-add cannot add classless PTR zones (#1058688)
- Move ipa-otpd socket directory to /var/run/krb5kdc (#1063850)

* Tue Feb  4 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-17
- Lockout plugin crashed during ipa-server-install (#912725)

* Fri Jan 31 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-16
- Fallback to global policy in ipa lockout plugin (#912725)
- Migration does not add users to default group (#903232)

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 3.3.3-15
- Mass rebuild 2014-01-24

* Thu Jan 23 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-14
- Fix NetBIOS name generation in CLDAP plugin (#1030517)

* Mon Jan 20 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-13
- Do not add krbPwdPolicyReference for new accounts, hardcode it (#1045218)
- Increase default timeout for IPA services (#1033273)
- Error while running trustdomain-find (#1054376)
- group-show lists SID instead of name for external groups (#1054391)
- Fix IPA server NetBIOS name in samba configuration (#1030517)
- dnsrecord-mod produces missing API version warning (#1054869)
- Hide trust-resolve command as internal (#1052860)
- Add Trust domain Web UI (#1054870)
- ipasam cannot delete multiple child trusted domains (#1056120)

* Wed Jan 15 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-12
- Missing objectclasses when empty password passed to host-add (#1052979)
- sudoOrder missing in sudoers (#1052983)
- Missing examples in sudorule help (#1049464)
- Client automount does not uninstall when fstore is empty (#910899)
- Error not clear for invalid realm given to trust-fetch-domains (#1052981)
- trust-fetch-domains does not add idrange for subdomains found (#1049926)
- Add option to show if an AD subdomain is enabled/disabled (#1052973)
- ipa-adtrust-install still failed with long NetBIOS names (#1030517)
- Error not clear for invalid relam given to trustdomain-find (#1049455)
- renewed client cert not recognized during IPA CA renewal (#1033273)

* Fri Jan 10 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-11
- hbactest does not work for external users (#848531)

* Wed Jan 08 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-10
- PKI service restart after CA renewal failed (#1040018)

* Mon Jan 06 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-9
- Move ipa-tests package to separate srpm (#1032668)

* Fri Jan  3 2014 Martin Kosek <mkosek@redhat.com> - 3.3.3-8
- Fix status trust-add command status message (#910453)
- NetBIOS was not trimmed at 15 characters (#1030517)
- Harden CA subsystem certificate renewal on CA clones (#1040018)

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 3.3.3-7
- Mass rebuild 2013-12-27

* Mon Dec  2 2013 Martin Kosek <mkosek@redhat.com> - 3.3.3-6
- Remove "Listen 443 http" hack from deployed nss.conf (#1029046)
- Re-adding existing trust fails (#1033216)
- IPA uninstall exits with a samba error (#1033075)
- Added RELRO hardening on /usr/libexec/ipa-otpd (#1026260)
- Fixed ownership of /usr/share/ipa/ui/js (#1026260)
- ipa-tests: support external names for hosts (#1032668)
- ipa-client-install fail due fail to obtain host TGT (#1029354)

* Fri Nov 22 2013 Martin Kosek <mkosek@redhat.com> - 3.3.3-5
- Trust add tries to add same value of --base-id for sub domain,
  causing an error (#1033068)
- Improved error reporting for adding trust case (#1029856)

* Wed Nov 13 2013 Martin Kosek <mkosek@redhat.com> - 3.3.3-4
- Winsync agreement cannot be created (#1023085)

* Wed Nov  6 2013 Martin Kosek <mkosek@redhat.com> - 3.3.3-3
- Installer did not detect different server and IPA domain (#1026845)
- Allow kernel keyring CCACHE when supported (#1026861)

* Tue Nov  5 2013 Martin Kosek <mkosek@redhat.com> - 3.3.3-2
- ipa-server-install crashes when AD subpackage is not installed (#1026434)

* Fri Nov  1 2013 Martin Kosek <mkosek@redhat.com> - 3.3.3-1
- Update to upstream 3.3.3 (#991064)

* Tue Oct 29 2013 Martin Kosek <mkosek@redhat.com> - 3.3.2-5
- Temporarily move ipa-backup and ipa-restore functionality
  back to make them available in public Beta (#1003933)

* Tue Oct 29 2013 Martin Kosek <mkosek@redhat.com> - 3.3.2-4
- Server install failure during client enrollment shouldn't
  roll back (#1023086)
- nsds5ReplicaStripAttrs are not set on agreements (#1023085)
- ipa-server conflicts with mod_ssl (#1018172)

* Wed Oct 16 2013 Martin Kosek <mkosek@redhat.com> - 3.3.2-3
- Reinstalling ipa server hangs when configuring certificate
  server (#1018804)

* Fri Oct 11 2013 Martin Kosek <mkosek@redhat.com> - 3.3.2-2
- Deprecate --serial-autoincrement option (#1016645)
- CA installation always failed on replica (#1005446)
- Re-initializing a winsync connection exited with error (#994980)

* Fri Oct  4 2013 Martin Kosek <mkosek@redhat.com> - 3.3.2-1
- Update to upstream 3.3.2 (#991064)
- Add delegation info to MS-PAC (#915799)
- Warn about incompatibility with AD when IPA realm and domain
  differs (#1009044)
- Allow PKCS#12 files with empty password in install tools (#1002639)
- Privilege "SELinux User Map Administrators" did not list
  permissions (#997085)
- SSH key upload broken when client joins an older server (#1009024)

* Mon Sep 23 2013 Martin Kosek <mkosek@redhat.com> - 3.3.1-5
- Remove dependency on python-paramiko (#1002884)
- Broken redirection when deleting last entry of DNS resource
  record (#1006360)

* Tue Sep 10 2013 Martin Kosek <mkosek@redhat.com> - 3.3.1-4
- Remove ipa-backup and ipa-restore functionality from RHEL (#1003933)

* Mon Sep  9 2013 Martin Kosek <mkosek@redhat.com> - 3.3.1-3
- Replica installation fails for RHEL 6.4 master (#1004680)
- Server uninstallation crashes if DS is not available (#998069)

* Thu Sep  5 2013 Martin Kosek <mkosek@redhat.com> - 3.3.1-2
- Unable to remove replica by ipa-replica-manage (#1001662)
- Before uninstalling a server, warn about active replicas (#998069)

* Thu Aug 29 2013 Rob Crittenden <rcritten@redhat.com> - 3.3.1-1
- Update to upstream 3.3.1 (#991064)
- Update minimum version of bind-dyndb-ldap to 3.5

* Tue Aug 20 2013 Rob Crittenden <rcritten@redhat.com> - 3.3.0-7
- Fix replica installation failing on certificate subject (#983075)

* Tue Aug 13 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-6
- Allow ipa-tests to work with older version (1.7.7) of python-paramiko

* Tue Aug 13 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-5
- Prevent multilib failures in *.pyo and *.pyc files

* Mon Aug 12 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-4
- ipa-server-install fails if --subject parameter is other than default
  realm (#983075)
- do not allow configuring bind-dyndb-ldap without persistent search (#967876)

* Mon Aug 12 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-3
- diffstat was missing as a build dependency causing multilib problems

* Thu Aug  8 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-2
- Remove ipa-server-selinux obsoletes as upgrades from version prior to
  3.3.0 are not allowed
- Wrap server-trust-ad subpackage description better
- Add (noreplace) flag for %%{_sysconfdir}/tmpfiles.d/ipa.conf
- Change permissions on default_encoding_utf8.so to fix ipa-python Provides

* Thu Aug  8 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-1
- Update to upstream 3.3.0 (#991064)

* Thu Aug  8 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-0.2.beta2
- Require slapi-nis 0.47.7 delivering a core feature of 3.3.0 release

* Wed Aug  7 2013 Martin Kosek <mkosek@redhat.com> - 3.3.0-0.1.beta2
- Update to upstream 3.3.0 Beta 2 (#991064)

* Thu Jul 18 2013 Martin Kosek <mkosek@redhat.com> - 3.2.2-1
- Update to upstream 3.2.2
- Drop ipa-server-selinux subpackage
- Drop redundant directory /var/cache/ipa/sessions
- Do not create /var/lib/ipa/pki-ca/publish, retain reference as ghost
- Run ipa-upgradeconfig and server restart in posttrans to avoid inconsistency
  issues when there are still old parts of software (like entitlements plugin)

* Fri Jun 14 2013 Martin Kosek <mkosek@redhat.com> - 3.2.1-1
- Update to upstream 3.2.1
- Drop dogtag-pki-server-theme requires, it won't be build for RHEL-7.0

* Tue May 14 2013 Rob Crittenden <rcritten@redhat.com> - 3.2.0-2
- Add OTP patches
- Add patch to set KRB5CCNAME for 389-ds-base

* Fri May 10 2013 Rob Crittenden <rcritten@redhat.com> - 3.2.0-1
- Update to upstream 3.2.0 GA
- ipa-client-install fails if /etc/ipa does not exist (#961483)
- Certificate status is not visible in Service and Host page (#956718)
- ipa-client-install removes needed options from ldap.conf (#953991)
- Handle socket.gethostbyaddr() exceptions when verifying hostnames (#953957)
- Add triggerin scriptlet to support OpenSSH 6.2 (#953617)
- Require nss 3.14.3-12.0 to address certutil certificate import
  errors (#953485)
- Require pki-ca 10.0.2-3 to pull in fix for sslget and mixed IPv4/6
  environments. (#953464)
- ipa-client-install removes 'sss' from /etc/nsswitch.conf (#953453)
- ipa-server-install --uninstall doesn't stop dirsrv instances (#953432)
- Add requires for openldap-2.4.35-4 to pickup fixed SASL_NOCANON behavior for
  socket based connections (#960222)
- Require libsss_nss_idmap-python
- Add Conflicts on nss-pam-ldapd < 0.8.4. The mapping from uniqueMember to
  member is now done automatically and having it in the config file raises
  an error.
- Add backup and restore tools, directory.
- require at least systemd 38 which provides the journal (we no longer
  need to require syslog.target)
- Update Requires on policycoreutils to 2.1.14-37
- Update Requires on selinux-policy to 3.12.1-42
- Update Requires on 389-ds-base to 1.3.1.0
- Remove a Requires for java-atk-wrapper

* Tue Apr 23 2013 Rob Crittenden <rcritten@redhat.com> - 3.2.0-0.4.beta1
- Remove release from krb5-server in strict sub-package to allow for rebuilds.

* Mon Apr 22 2013 Rob Crittenden <rcritten@redhat.com> - 3.2.0-0.3.beta1
- Add a Requires for java-atk-wrapper until we can determine which package
  should be pulling it in, dogtag or tomcat.

* Tue Apr 16 2013 Rob Crittenden <rcritten@redhat.com> - 3.2.0-0.2.beta1
- Update to upstream 3.2.0 Beta 1

* Tue Apr  2 2013 Martin Kosek <mkosek@redhat.com> - 3.2.0-0.1.pre1
- Update to upstream 3.2.0 Prerelease 1
- Use upstream reference spec file as a base for Fedora spec file

* Sat Mar 30 2013 Kevin Fenzi <kevin@scrye.com> 3.1.2-4
- Rebuild for broken deps
- Fix 389-ds-base strict dep to be 1.3.0.5 and krb5-server 1.11.1

* Sat Feb 23 2013 Kevin Fenzi <kevin@scrye.com> - 3.1.2-3
- Rebuild for broken deps in rawhide
- Fix 389-ds-base strict dep to be 1.3.0.3

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.1.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Wed Jan 23 2013 Rob Crittenden <rcritten@redhat.com> - 3.1.2-1
- Update to upstream 3.1.2
- CVE-2012-4546: Incorrect CRLs publishing
- CVE-2012-5484: MITM Attack during Join process
- CVE-2013-0199: Cross-Realm Trust key leak
- Updated strict dependencies to 389-ds-base = 1.3.0.2 and
  pki-ca = 10.0.1

* Thu Dec 20 2012 Martin Kosek <mkosek@redhat.com> - 3.1.0-2
- Remove redundat Requires versions that are already in Fedora 17
- Replace python-crypto Requires with m2crypto
- Add missing Requires(post) for client and server-trust-ad subpackages
- Restart httpd service when server-trust-ad subpackage is installed
- Bump selinux-policy Requires to pick up PKI/LDAP port labeling fixes

* Mon Dec 10 2012 Rob Crittenden <rcritten@redhat.com> - 3.1.0-1
- Updated to upstream 3.1.0 GA
- Set minimum for sssd to 1.9.2
- Set minimum for pki-ca to 10.0.0-1
- Set minimum for 389-ds-base to 1.3.0
- Set minimum for selinux-policy to 3.11.1-60
- Remove unneeded dogtag package requires

* Tue Oct 23 2012 Martin Kosek <mkosek@redhat.com> - 3.0.0-3
- Update Requires on krb5-server to 1.11

* Fri Oct 12 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-2
- Configure CA replication to use TLS instead of SSL

* Fri Oct 12 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-1
- Updated to upstream 3.0.0 GA
- Set minimum for samba to 4.0.0-153.
- Make sure server-trust-ad subpackage alternates winbind_krb5_locator.so
  plugin to /dev/null since they cannot be used when trusts are configured
- Restrict krb5-server to 1.10.
- Update BR for 389-ds-base to 1.3.0
- Add directory /var/lib/ipa/pki-ca/publish for CRL published by pki-ca
- Add Requires on zip for generating FF browser extension

* Fri Oct  5 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-0.10
- Updated to upstream 3.0.0 rc 2
- Include new FF configuration extension
- Set minimum Requires of selinux-policy to 3.11.1-33
- Set minimum Requires dogtag to 10.0.0-0.43.b1
- Add new optional strict sub-package to allow users to limit other
  package upgrades.

* Tue Oct  2 2012 Martin Kosek <mkosek@redhat.com> - 3.0.0-0.9
- Require samba packages instead of obsoleted samba4 packages

* Fri Sep 21 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-0.8
- Updated to upstream 3.0.0 rc 1
- Update BR for 389-ds-base to 1.2.11.14
- Update BR for krb5 to 1.10
- Update BR for samba4-devel to 4.0.0-139 (rc1)
- Add BR for python-polib
- Update BR and Requires on sssd to 1.9.0
- Update Requires on policycoreutils to 2.1.12-5
- Update Requires on 389-ds-base to 1.2.11.14
- Update Requires on selinux-policy to 3.11.1-21
- Update Requires on dogtag to 10.0.0-0.33.a1
- Update Requires on certmonger to 0.60
- Update Requires on tomcat to 7.0.29
- Update minimum version of bind to 9.9.1-10.P3
- Update minimum version of bind-dyndb-ldap to 1.1.0-0.16.rc1
- Remove Requires on authconfig from python sub-package

* Wed Sep  5 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-0.7
- Rebuild against samba4 beta8

* Fri Aug 31 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-0.6
- Rebuild against samba4 beta7

* Wed Aug 22 2012 Alexander Bokovoy <abokovoy@redhat.com> - 3.0.0-0.5
- Adopt to samba4 beta6 (libsecurity -> libsamba-security)
- Add dependency to samba4-winbind

* Fri Aug 17 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-0.4
- Updated to upstream 3.0.0 beta 2

* Mon Aug  6 2012 Martin Kosek <mkosek@redhat.com> - 3.0.0-0.3
- Updated to current upstream state of 3.0.0 beta 2 development

* Mon Jul 23 2012 Alexander Bokovoy <abokovy@redhat.com> - 3.0.0-0.2
- Rebuild against samba4 beta4

* Mon Jul  2 2012 Rob Crittenden <rcritten@redhat.com> - 3.0.0-0.1
- Updated to upstream 3.0.0 beta 1

* Thu May  3 2012 Rob Crittenden <rcritten@redhat.com> - 2.2.0-1
- Updated to upstream 2.2.0 GA
- Update minimum n-v-r of certmonger to 0.53
- Update minimum n-v-r of slapi-nis to 0.40
- Add Requires in client to oddjob-mkhomedir and python-krbV
- Update minimum selinux-policy to 3.10.0-110

* Mon Mar 19 2012 Rob Crittenden <rcritten@redhat.com> - 2.1.90-0.2
- Update to upstream 2.2.0 beta 1 (2.1.90.rc1)
- Set minimum n-v-r for pki-ca and pki-silent to 9.0.18.
- Add Conflicts on mod_ssl
- Update minimum n-v-r of 389-ds-base to 1.2.10.4
- Update minimum n-v-r of sssd to 1.8.0
- Update minimum n-v-r of slapi-nis to 0.38
- Update minimum n-v-r of pki-* to 9.0.18
- Update conflicts on bind-dyndb-ldap to < 1.1.0-0.9.b1
- Update conflicts on bind to < 9.9.0-1
- Drop requires on krb5-server-ldap
- Add patch to remove escaping arguments to pkisilent

* Mon Feb 06 2012 Rob Crittenden <rcritten@redhat.com> - 2.1.90-0.1
- Update to upstream 2.2.0 alpha 1 (2.1.90.pre1)

* Wed Feb 01 2012 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.4-5
- Force to use 389-ds 1.2.10-0.8.a7 or above
- Improve upgrade script to handle systemd 389-ds change
- Fix freeipa to work with python-ldap 2.4.6

* Wed Jan 11 2012 Martin Kosek <mkosek@redhat.com> - 2.1.4-4
- Fix ipa-replica-install crashes
- Fix ipa-server-install and ipa-dns-install logging
- Set minimum version of pki-ca to 9.0.17 to fix sslget problem
  caused by FEDORA-2011-17400 update (#771357)

* Wed Dec 21 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.4-3
- Allow Web-based migration to work with tightened SE Linux policy (#769440)
- Rebuild slapi plugins against re-enterant version of libldap

* Sun Dec 11 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.4-2
- Allow longer dirsrv startup with systemd:
  - IPAdmin class will wait until dirsrv instance is available up to 10 seconds
  - Helps with restarts during upgrade for ipa-ldap-updater
- Fix pylint warnings from F16 and Rawhide

* Tue Dec  6 2011 Rob Crittenden <rcritten@redhat.com> - 2.1.4-1
- Update to upstream 2.1.4 (CVE-2011-3636)

* Mon Dec  5 2011 Rob Crittenden <rcritten@redhat.com> - 2.1.3-8
- Update SELinux policy to allow ipa_kpasswd to connect ldap and
  read /dev/urandom. (#759679)

* Wed Nov 30 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.3-7
- Fix wrong path in packaging freeipa-systemd-upgrade

* Wed Nov 30 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.3-6
- Introduce upgrade script to recover existing configuration after systemd migration
  as user has no means to recover FreeIPA from systemd migration
- Upgrade script:
  - recovers symlinks in Dogtag instance install
  - recovers systemd configuration for FreeIPA's directory server instances
  - recovers freeipa.service
  - migrates directory server and KDC configs to use proper keytabs for systemd services

* Wed Oct 26 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.1.3-5
- Rebuilt for glibc bug#747377

* Wed Oct 19 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.3-4
- clean up spec
- Depend on sssd >= 1.6.2 for better user experience

* Tue Oct 18 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.3-3
- Fix Fedora package changelog after merging systemd changes

* Tue Oct 18 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.3-2
- Fix postin scriplet for F-15/F-16

* Tue Oct 18 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.3-1
- 2.1.3

* Mon Oct 17 2011 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.2-1
- Default to systemd for Fedora 16 and onwards

* Tue Aug 16 2011 Rob Crittenden <rcritten@redhat.com> - 2.1.0-1
- Update to upstream 2.1.0

* Fri May  6 2011 Simo Sorce <ssorce@redhat.com> - 2.0.1-2
- Fix bug #702633

* Mon May  2 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.1-1
- Update minimum selinux-policy to 3.9.16-18
- Update minimum pki-ca and pki-selinux to 9.0.7
- Update minimum 389-ds-base to 1.2.8.0-1
- Update to upstream 2.0.1

* Thu Mar 24 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.0-1
- Update to upstream GA release
- Automatically apply updates when the package is upgraded

* Fri Feb 25 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.0-0.4.rc2
- Update to upstream freeipa-2.0.0.rc2
- Set minimum version of python-nss to 0.11 to make sure IPv6 support is in
- Set minimum version of sssd to 1.5.1
- Patch to include SuiteSpotGroup when setting up 389-ds instances
- Move a lot of BuildRequires so this will build with ONLY_CLIENT enabled

* Tue Feb 15 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.0-0.3.rc1
- Set the N-V-R so rc1 is an update to beta2.

* Mon Feb 14 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.0-0.1.rc1
- Set minimum version of sssd to 1.5.1
- Update to upstream freeipa-2.0.0.rc1
- Move server-only binaries from admintools subpackage to server

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0.0-0.2.beta2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Thu Feb  3 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.0-0.1.beta2
- Set min version of 389-ds-base to 1.2.8
- Set min version of mod_nss 1.0.8-10
- Set min version of selinux-policy to 3.9.7-27
- Add dogtag themes to Requires
- Update to upstream freeipa-2.0.0.pre2

* Thu Jan 27 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.0-0.2.beta.git80e87e7
- Remove unnecessary moving of v1 CA serial number file in post script
- Add Obsoletes for server-selinxu subpackage
- Using git snapshot 442d6ad30ce1156914e6245aa7502499e50ec0da

* Wed Jan 26 2011 Rob Crittenden <rcritten@redhat.com> - 2.0.0-0.1.beta.git80e87e7
- Prepare spec file for release
- Using git snapshot 80e87e75bd6ab56e3e20c49ece55bd4d52f1a503

* Tue Jan 25 2011 Rob Crittenden <rcritten@redhat.com> - 1.99-41
- Re-arrange doc and defattr to clean up rpmlint warnings
- Remove conditionals on older releases
- Move some man pages into admintools subpackage
- Remove some explicit Requires in client that aren't needed
- Consistent use of buildroot vs RPM_BUILD_ROOT

* Wed Jan 19 2011 Adam Young <ayoung@redhat.com> - 1.99-40
- Moved directory install/static to install/ui

* Thu Jan 13 2011 Simo Sorce <ssorce@redhat.com> - 1.99-39
- Remove dependency on nss_ldap/nss-pam-ldapd
- The official client is sssd and that's what we use by default.

* Thu Jan 13 2011 Simo Sorce <ssorce@redhat.com> - 1.99-38
- Remove radius subpackages

* Thu Jan 13 2011 Rob Crittenden <rcritten@redhat.com> - 1.99-37
- Set minimum pki-ca and pki-silent versions to 9.0.0

* Wed Jan 12 2011 Rob Crittenden <rcritten@redhat.com> - 1.99-36
- Drop BuildRequires on mozldap-devel

* Mon Dec 13 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-35
- Add Requires on krb5-pkinit-openssl

* Fri Dec 10 2010 Jr Aquino <jr.aquino@citrix.com> - 1.99-34
- Add ipa-host-net-manage script

* Tue Dec  7 2010 Simo Sorce <ssorce@redhat.com> - 1.99-33
- Add ipa init script

* Fri Nov 19 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-32
- Set minimum level of 389-ds-base to 1.2.7 for enhanced memberof plugin

* Wed Nov  3 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-31
- remove ipa-fix-CVE-2008-3274

* Wed Oct  6 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-30
- Remove duplicate %%files entries on share/ipa/static
- Add python default encoding shared library

* Mon Sep 20 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-29
- Drop requires on python-configobj (not used any more)
- Drop ipa-ldap-updater message, upgrades are done differently now

* Wed Sep  8 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-28
- Drop conflicts on mod_nss
- Require nss-pam-ldapd on F-14 or higher instead of nss_ldap (#606847)
- Drop a slew of conditionals on older Fedora releases (< 12)
- Add a few conditionals against RHEL 6
- Add Requires of nss-tools on ipa-client

* Fri Aug 13 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-27
- Set minimum version of certmonger to 0.26 (to pck up #621670)
- Set minimum version of pki-silent to 1.3.4 (adds -key_algorithm)
- Set minimum version of pki-ca to 1.3.6
- Set minimum version of sssd to 1.2.1

* Tue Aug 10 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-26
- Add BuildRequires for authconfig

* Mon Jul 19 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-25
- Bump up minimum version of python-nss to pick up nss_is_initialize() API

* Thu Jun 24 2010 Adam Young <ayoung@redhat.com> - 1.99-24
- Removed python-asset based webui

* Thu Jun 24 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-23
- Change Requires from fedora-ds-base to 389-ds-base
- Set minimum level of 389-ds-base to 1.2.6 for the replication
  version plugin.

* Tue Jun  1 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-22
- Drop Requires of python-krbV on ipa-client

* Mon May 17 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-21
- Load ipa_dogtag.pp in post install

* Mon Apr 26 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-20
- Set minimum level of sssd to 1.1.1 to pull in required hbac fixes.

* Thu Mar  4 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-19
- No need to create /var/log/ipa_error.log since we aren't using
  TurboGears any more.

* Mon Mar 1 2010 Jason Gerard DeRose <jderose@redhat.com> - 1.99-18
- Fixed share/ipa/wsgi.py so .pyc, .pyo files are included

* Wed Feb 24 2010 Jason Gerard DeRose <jderose@redhat.com> - 1.99-17
- Added Require mod_wsgi, added share/ipa/wsgi.py

* Thu Feb 11 2010 Jason Gerard DeRose <jderose@redhat.com> - 1.99-16
- Require python-wehjit >= 0.2.2

* Wed Feb  3 2010 Rob Crittenden <rcritten@redhat.com> - 1.99-15
- Add sssd and certmonger as a Requires on ipa-client

* Wed Jan 27 2010 Jason Gerard DeRose <jderose@redhat.com> - 1.99-14
- Require python-wehjit >= 0.2.0

* Fri Dec  4 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-13
- Add ipa-rmkeytab tool

* Tue Dec  1 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-12
- Set minimum of python-pyasn1 to 0.0.9a so we have support for the ASN.1
  Any type

* Wed Nov 25 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-11
- Remove v1-style /etc/ipa/ipa.conf, replacing with /etc/ipa/default.conf

* Fri Nov 13 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-10
- Add bash completion script and own /etc/bash_completion.d in case it
  doesn't already exist

* Tue Nov  3 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-9
- Remove ipa_webgui, its functions rolled into ipa_httpd

* Mon Oct 12 2009 Jason Gerard DeRose <jderose@redhat.com> - 1.99-8
- Removed python-cherrypy from BuildRequires and Requires
- Added Requires python-assets, python-wehjit

* Mon Aug 24 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-7
- Added httpd SELinux policy so CRLs can be read

* Thu May 21 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-6
- Move ipalib to ipa-python subpackage
- Bump minimum version of slapi-nis to 0.15

* Wed May  6 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-5
- Set 0.14 as minimum version for slapi-nis

* Wed Apr 22 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-4
- Add Requires: python-nss to ipa-python sub-package

* Thu Mar  5 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-3
- Remove the IPA DNA plugin, use the DS one

* Wed Mar  4 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-2
- Build radius separately
- Fix a few minor issues

* Tue Feb  3 2009 Rob Crittenden <rcritten@redhat.com> - 1.99-1
- Replace TurboGears requirement with python-cherrypy

* Sat Jan 17 2009 Tomas Mraz <tmraz@redhat.com> - 1.2.1-3
- rebuild with new openssl

* Fri Dec 19 2008 Dan Walsh <dwalsh@redhat.com> - 1.2.1-2
- Fix SELinux code

* Mon Dec 15 2008 Simo Sorce <ssorce@redhat.com> - 1.2.1-1
- Fix breakage caused by python-kerberos update to 1.1

* Fri Dec 5 2008 Simo Sorce <ssorce@redhat.com> - 1.2.1-0
- New upstream release 1.2.1

* Sat Nov 29 2008 Ignacio Vazquez-Abrams <ivazqueznet+rpm@gmail.com> - 1.2.0-4
- Rebuild for Python 2.6

* Fri Nov 14 2008 Simo Sorce <ssorce@redhat.com> - 1.2.0-3
- Respin after the tarball has been re-released upstream
  New hash is 506c9c92dcaf9f227cba5030e999f177

* Thu Nov 13 2008 Simo Sorce <ssorce@redhat.com> - 1.2.0-2
- Conditionally restart also dirsrv and httpd when upgrading

* Wed Oct 29 2008 Rob Crittenden <rcritten@redhat.com> - 1.2.0-1
- Update to upstream version 1.2.0
- Set fedora-ds-base minimum version to 1.1.3 for winsync header
- Set the minimum version for SELinux policy
- Remove references to Fedora 7

* Wed Jul 23 2008 Simo Sorce <ssorce@redhat.com> - 1.1.0-3
- Fix for CVE-2008-3274
- Fix segfault in ipa-kpasswd in case getifaddrs returns a NULL interface
- Add fix for bug #453185
- Rebuild against openldap libraries, mozldap ones do not work properly
- TurboGears is currently broken in rawhide. Added patch to not build
  the UI locales and removed them from the ipa-server files section.

* Wed Jun 18 2008 Rob Crittenden <rcritten@redhat.com> - 1.1.0-2
- Add call to /usr/sbin/upgradeconfig to post install

* Wed Jun 11 2008 Rob Crittenden <rcritten@redhat.com> - 1.1.0-1
- Update to upstream version 1.1.0
- Patch for indexing memberof attribute
- Patch for indexing uidnumber and gidnumber
- Patch to change DNA default values for replicas
- Patch to fix uninitialized variable in ipa-getkeytab

* Fri May 16 2008 Rob Crittenden <rcritten@redhat.com> - 1.0.0-5
- Set fedora-ds-base minimum version to 1.1.0.1-4 and mod_nss minimum
  version to 1.0.7-4 so we pick up the NSS fixes.
- Add selinux-policy-base(post) to Requires (446496)

* Tue Apr 29 2008 Rob Crittenden <rcritten@redhat.com> - 1.0.0-4
- Add missing entry for /var/cache/ipa/kpasswd (444624)
- Added patch to fix permissions problems with the Apache NSS database.
- Added patch to fix problem with DNS querying where the query could be
  returned as the answer.
- Fix spec error where patch1 was in the wrong section

* Fri Apr 25 2008 Rob Crittenden <rcritten@redhat.com> - 1.0.0-3
- Added patch to fix problem reported by ldapmodify

* Fri Apr 25 2008 Rob Crittenden <rcritten@redhat.com> - 1.0.0-2
- Fix Requires for krb5-server that was missing for Fedora versions > 9
- Remove quotes around test for fedora version to package egg-info

* Fri Apr 18 2008 Rob Crittenden <rcritten@redhat.com> - 1.0.0-1
- Update to upstream version 1.0.0

* Tue Mar 18 2008 Rob Crittenden <rcritten@redhat.com> 0.99-12
- Pull upstream changelog 722
- Add Conflicts mod_ssl (435360)

* Fri Feb 29 2008 Rob Crittenden <rcritten@redhat.com> 0.99-11
- Pull upstream changelog 698
- Fix ownership of /var/log/ipa_error.log during install (435119)
- Add pwpolicy command and man page

* Thu Feb 21 2008 Rob Crittenden <rcritten@redhat.com> 0.99-10
- Pull upstream changelog 678
- Add new subpackage, ipa-server-selinux
- Add Requires: authconfig to ipa-python (bz #433747)
- Package i18n files

* Mon Feb 18 2008 Rob Crittenden <rcritten@redhat.com> 0.99-9
- Pull upstream changelog 641
- Require minimum version of krb5-server on F-7 and F-8
- Package some new files

* Thu Jan 31 2008 Rob Crittenden <rcritten@redhat.com> 0.99-8
- Marked with wrong license. IPA is GPLv2.

* Tue Jan 29 2008 Rob Crittenden <rcritten@redhat.com> 0.99-7
- Ensure that /etc/ipa exists before moving user-modifiable html files there
- Put html files into /etc/ipa/html instead of /etc/ipa

* Tue Jan 29 2008 Rob Crittenden <rcritten@redhat.com> 0.99-6
- Pull upstream changelog 608 which renamed several files

* Thu Jan 24 2008 Rob Crittenden <rcritten@redhat.com> 0.99-5
- package the sessions dir /var/cache/ipa/sessions
- Pull upstream changelog 597

* Thu Jan 24 2008 Rob Crittenden <rcritten@redhat.com> 0.99-4
- Updated upstream pull (596) to fix bug in ipa_webgui that was causing the
  UI to not start.

* Thu Jan 24 2008 Rob Crittenden <rcritten@redhat.com> 0.99-3
- Included LICENSE and README in all packages for documentation
- Move user-modifiable content to /etc/ipa and linked back to
  /usr/share/ipa/html
- Changed some references to /usr to the {_usr} macro and /etc
  to {_sysconfdir}
- Added popt-devel to BuildRequires for Fedora 8 and higher and
  popt for Fedora 7
- Package the egg-info for Fedora 9 and higher for ipa-python

* Tue Jan 22 2008 Rob Crittenden <rcritten@redhat.com> 0.99-2
- Added auto* BuildRequires

* Mon Jan 21 2008 Rob Crittenden <rcritten@redhat.com> 0.99-1
- Unified spec file

* Thu Jan 17 2008 Rob Crittenden <rcritten@redhat.com> - 0.6.0-2
- Fixed License in specfile
- Include files from /usr/lib/python*/site-packages/ipaserver

* Fri Dec 21 2007 Karl MacMillan <kmacmill@redhat.com> - 0.6.0-1
- Version bump for release

* Wed Nov 21 2007 Karl MacMillan <kmacmill@mentalrootkit.com> - 0.5.0-1
- Preverse mode on ipa-keytab-util
- Version bump for relase and rpm name change

* Thu Nov 15 2007 Rob Crittenden <rcritten@redhat.com> - 0.4.1-2
- Broke invididual Requires and BuildRequires onto separate lines and
  reordered them
- Added python-tgexpandingformwidget as a dependency
- Require at least fedora-ds-base 1.1

* Thu Nov  1 2007 Karl MacMillan <kmacmill@redhat.com> - 0.4.1-1
- Version bump for release

* Wed Oct 31 2007 Karl MacMillan <kmacmill@redhat.com> - 0.4.0-6
- Add dep for freeipa-admintools and acl

* Wed Oct 24 2007 Rob Crittenden <rcritten@redhat.com> - 0.4.0-5
- Add dependency for python-krbV

* Fri Oct 19 2007 Rob Crittenden <rcritten@redhat.com> - 0.4.0-4
- Require mod_nss-1.0.7-2 for mod_proxy fixes

* Thu Oct 18 2007 Karl MacMillan <kmacmill@redhat.com> - 0.4.0-3
- Convert to autotools-based build

* Tue Sep 25 2007 Karl MacMillan <kmacmill@redhat.com> - 0.4.0-2

* Fri Sep 7 2007 Karl MacMillan <kmacmill@redhat.com> - 0.3.0-1
- Added support for libipa-dna-plugin

* Fri Aug 10 2007 Karl MacMillan <kmacmill@redhat.com> - 0.2.0-1
- Added support for ipa_kpasswd and ipa_pwd_extop

* Sun Aug  5 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-3
- Abstracted client class to work directly or over RPC

* Wed Aug  1 2007 Rob Crittenden <rcritten@redhat.com> - 0.1.0-2
- Add mod_auth_kerb and cyrus-sasl-gssapi to Requires
- Remove references to admin server in ipa-server-setupssl
- Generate a client certificate for the XML-RPC server to connect to LDAP with
- Create a keytab for Apache
- Create an ldif with a test user
- Provide a certmap.conf for doing SSL client authentication

* Fri Jul 27 2007 Karl MacMillan <kmacmill@redhat.com> - 0.1.0-1
- Initial rpm version
