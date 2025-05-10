# ocidist-regproxy

This project exposes a [`containers-storage:`](https://github.com/containers/storage)
as used by e.g. [podman](https://github.com/containers/podman) via the standard
[OCI distribution spec](https://github.com/opencontainers/distribution-spec)
AKA a registry.

The registry is read-only.

## Use cases

- Have local virtual machines be able to easily fetch content from the
  host container storage.

## Running

### Bind mounting container storage

You need to bind mount wherever your host container storage is into `/var/lib/containers/storage`
in the container. For example with rootless podman, that's `~/.local/share/containers/storage`.

For rootful podman, it's the same `/var/lib/containers/storage`.

### Privileges

Because this command requires write access to the storage in order to perform
locking (for bad reasons, this will be fixed) *and* to handle SELinux labeling,
this container requires `--privileged`.

### Port mapping

The container listens on port 8000; you can expose this on whatever port you like.

### Example

```
$ podman run --name regproxy --privileged --rm -d -p 8000:8000 -v ~/.local/share/containers/storage/:/var/lib/containers/storage ghcr.io/cgwalters/ocidist-localproxy:latest
```

## Accessing the registry

Note that unless you go to extra effort, the server will not speak TLS.
For example with `skopeo` you must use e.g. `--src-tls-verify=false`.

Example: `skopeo copy --src-tls-verify=false docker://127.0.0.1:8000/quay.io/fedora/fedora:latest oci:/tmp/foo.oci`
