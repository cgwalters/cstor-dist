# ocidist-regproxy

This project exposes a [`containers-storage:`](https://github.com/containers/storage)
as used by e.g. [podman](https://github.com/containers/podman) via the standard
[OCI distribution spec](https://github.com/opencontainers/distribution-spec)
AKA a registry.

The registry is read-only.

## Use cases

- Have local virtual machines be able to easily fetch content from the
  host container storage.
