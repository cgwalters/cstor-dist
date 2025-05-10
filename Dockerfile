# Build a binary of skopeo from my fork, plus download runtime dependencies
# that aren't in ubi9. Output goes in /out/
FROM registry.access.redhat.com/ubi9/ubi:latest as build-skopeo
WORKDIR /src
# Only copy these to ensure layer caching works
COPY dependencies.txt /src
RUN <<EORUN
set -xeuo pipefail
# Download runtime deps
mkdir /out-rpms
cd /out-rpms
grep -vE -e '^#' /src/dependencies.txt | xargs dnf -y download --arch=$(arch)
# Install skopeo build deps
dnf -y install golang make git-core 'pkgconfig(gpgme)'
EORUN
RUN git clone --depth=1 https://github.com/cgwalters/skopeo -b get-raw-blob
RUN <<EORUN
set -xeuo pipefail
cd skopeo
make bin/skopeo
mkdir -p /out
install -D -m 0755 -t /out/usr/bin ./bin/skopeo
EORUN

# Build this project and install the binaries in /out/
FROM registry.access.redhat.com/ubi9/ubi:latest as build
WORKDIR /src
# Only copy these to ensure layer caching works
COPY build-dependencies.txt /src
RUN <<EORUN
set -xeuo pipefail
# Build dependencies
grep -vE -e '^#' /src/build-dependencies.txt | xargs dnf -y install
EORUN
# Only now copy the full source code so source changes don't blow out the package caches
COPY . /src
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
RUN --mount=type=cache,target=/src/target \ 
    --mount=type=cache,target=/root \
    make && make install DESTDIR=/out/

# Merge the above two builds into a single runtime image.
FROM registry.access.redhat.com/ubi9/ubi:latest
# Install target dependencies we downloaded in the build phase.
RUN --mount=type=bind,from=build-skopeo,target=/build rpm -ivh /build/out-rpms/*.rpm
# Install target dependencies we downloaded in the build phase.
COPY --from=build-skopeo /out/ /
COPY --from=build /out/ /
# This is the default port
EXPOSE 8000
CMD ["/usr/bin/ocidist-localproxy"]

