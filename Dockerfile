FROM nixos/nix:2.35.2

# Enable flakes and parallel local builds
RUN printf '%s\n' 'experimental-features = nix-command flakes' 'max-jobs = auto' \
  >> /etc/nix/nix.conf

WORKDIR /typenet
COPY flake.nix flake.lock ./

# Prefetch the toolchain so the first container start is fast. Also link `/etc/protocols` (missing
# from the base image) from the flake's pinned nixpkgs because inetutils' `ping` needs it.
RUN nix develop .#docker --command true \
  && nix build --inputs-from . --out-link /etc/iana-etc nixpkgs#iana-etc \
  && ln -s /etc/iana-etc/etc/protocols /etc/protocols

CMD ["nix", "develop", ".#docker"]
