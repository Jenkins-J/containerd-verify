# containerd verify

This is a ttrpc plugin made for containerd that verifies container images.
This plugin is a minimal implementation, using packages from the 
[Notary Project](https://notaryproject.dev/docs/quickstart/) in order to 
integrate the image signature verification functionality of the 
[Notation](https://github.com/notaryproject/notation) tool into containerd.

This plugin is based on the work done in pull request #6994 of the 
[containerd](https://github.com/containerd/containerd) project.