## The sudo philosophy

Sudo is a program designed to allow a sysadmin to give limited root privileges
to users and log root activity.  The basic philosophy is to give as few
privileges as possible but still allow people to get their work done.

## Where to find sudo

Before you try and build sudo, *please* make sure you have the current
version.  The latest sudo may always be gotten via anonymous ftp from
ftp.sudo.ws in the directory /pub/sudo/ or from the sudo web site,
https://www.sudo.ws/

The distribution is sudo-M.m.tar.gz where _M_ is the major version
number and _m_ is the minor version number.  Beta versions of sudo may
also be available.  If you join the _sudo-workers_ mailing list you
will get the beta announcements (see the Mailing lists section below).

## What's new

See the NEWS file for a list of major changes in this release.  For
a complete list of changes, see the [ChangeLog](ChangeLog).
For a summary of major changes to the current stable release, see
https://www.sudo.ws/releases/stable/.

If you are upgrading from an earlier version of Sudo, please read
[docs/UPGRADE.md](docs/UPGRADE.md) for information on changes in
behavior that may affect you.

For a history of sudo please see [docs/HISTORY.md](docs/HISTORY.md).
You can find a list of contributors to sudo in
[docs/CONTRIBUTORS.md](docs/CONTRIBUTORS.md).

## Building the release

Please read the installation guide, [INSTALL.md](INSTALL.md), before
trying to build sudo.  Pay special attention to the "OS dependent notes"
section.

## How to contribute

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for information on
how you can help contribute to sudo.

## Copyright

Sudo is distributed under an ISC-style license.
Please refer to [LICENSE.md](LICENSE.md) for details.

## Mailing lists

#### sudo-announce

This list receives announcements whenever a new version of sudo is
released.  https://www.sudo.ws/mailman/listinfo/sudo-announce

#### sudo-blog

This list receives a message when a new sudo blog article is
available.  https://www.sudo.ws/mailman/listinfo/sudo-blog

#### sudo-commits

This list receives a message for each commit made to the sudo source
repository.  https://www.sudo.ws/mailman/listinfo/sudo-commits

#### sudo-users

This list is for questions and general discussion about sudo.
https://www.sudo.ws/mailman/listinfo/sudo-users

#### sudo-workers

This list is for people working on and porting sudo.
https://www.sudo.ws/mailman/listinfo/sudo-workers

To subscribe to a list, visit its url (listed above) and enter your
email address to subscribe.  Digest versions are available but these are
fairly low traffic lists so the digest versions are not a significant win.

Mailing list archives are also available.  See the mailing list web sites
for the appropriate links.

## Web page

There is a sudo web page at https://www.sudo.ws/ that contains an overview
of sudo, documentation, downloads, a bug tracker, the sudo blog, information
about beta versions and other useful info.

## Bug reports

If you have found what you believe to be a bug, you can file a bug
report in the sudo bug database, at https://bugzilla.sudo.ws/.
Alternately, you can file a GitHub issue if that is easier for you
at https://github.com/sudo-project/sudo/issues/.

Please see [docs/SECURITY.md](docs/SECURITY.md) for our security
policy and how to report security issues.

Please read over [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
*before* submitting a bug report.  When reporting bugs, please be
sure to include the version of sudo you are using as well as the
platform you are running it on.
