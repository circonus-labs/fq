FROM centos:centos7.9.2009 AS centos

WORKDIR /src/fq
COPY . ./

RUN yum -y install gcc make

RUN yum -y install sqlite
COPY Circonus.repo /etc/yum.repos.d/
RUN rpm --import https://keybase.io/circonuspkg/pgp_keys.asc?fingerprint=14ff6826503494d85e62d2f22dd15eba6d4fa648
RUN yum -y install circonus-platform-library-bcd circonus-platform-library-jlog circonus-platform-library-liblz4 circonus-platform-library-uuid circonus-platform-runtime-luajit

RUN LDFLAGS="-static -static-libgcc -static-libstdc++" make

RUN useradd -u 65534 nobody

FROM scratch
WORKDIR /
COPY --from=centos /etc/passwd /etc/passwd
COPY --from=centos /src/fq/fqd /fqd
USER nobody
ENTRYPOINT ["/fqd"]
CMD ["-D"]
