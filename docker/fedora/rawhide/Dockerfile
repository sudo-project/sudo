FROM docker.io/library/fedora:rawhide
ENV TZ=America/Denver

RUN dnf -y install audit-libs-devel cyrus-sasl-devel glibc-devel \
    libselinux-devel libsepol-devel openldap-devel openssl-devel pam-devel \
    python3-devel rpm-build zlib-devel binutils ed gcc gdb git openssh \
    procps which
RUN useradd -ms /bin/bash build
