####################################################################################################
# Config
####################################################################################################

set dotenv-load

project-name := 'typenet'
user := env('USER')

server-addr := '10.0.0.2'
server-port := '8080'

# NOTE: "TYPENET_TUN_NAME" is also read by the server with a "tun0" fallback
tun-name := env('TYPENET_TUN_NAME', 'tun0')
tun-cidr := env('TYPENET_TUN_CIDR', '10.0.0.1/24')

logs-dir := justfile_dir() / 'logs'
log-file := logs-dir / project-name + '_' + datetime('%F_%T') + '.log'
pcap-dir := justfile_dir() / 'pcap'
pcap-file := pcap-dir / project-name + '_' + datetime('%F_%T') + '.pcap'
blob-dir := justfile_dir() / 'blob'
blob-file := blob-dir / 'random.bin'

tshark-cmd := 'tshark -n --print' \
    + ' -o ip.check_checksum:true -o tcp.check_checksum:true -o udp.check_checksum:true'

####################################################################################################
# Running the server (including TUN device setup)
####################################################################################################

# Run the server (default recipe)
[continue]
serve *ARGS: tun
    cargo run {{ ARGS }}

# Run the server and save a log file to the `logs` directory
[continue]
serve-save *ARGS:
    mkdir -p '{{ logs-dir }}'
    just serve "{{ ARGS }} --quiet 2>&1 | tee --ignore-interrupts --append '{{ log-file }}'"
    @echo 'Saved to {{ log-file }}'

# Remove the `logs` directory
log-clean:
    rm -rf '{{ logs-dir }}'

# Create the TUN device if it doesn't already exist
tun:
    @if ! ip addr show {{ tun-name }} >/dev/null 2>&1; then \
        echo 'TUN device {{ tun-name }} not found'; \
        just tun-create; \
    fi

# Internal helper for the `tun` recipe (also used in CI for unconditional creation)
[private]
[confirm(f'Create TUN device {{ tun-name }}? (uses sudo)')]
tun-create:
    sudo ip tuntap add dev {{ tun-name }} mode tun user {{ user }}
    sudo ip addr add {{ tun-cidr }} dev {{ tun-name }}
    sudo ip link set {{ tun-name }} up
    @echo 'TUN device created: name={{ tun-name }}, CIDR={{ tun-cidr }}, user={{ user }}'

# Remove the TUN device manually instead of waiting for it to be destroyed on reboot (uses sudo)
tun-del:
    sudo ip link del {{ tun-name }}

####################################################################################################
# Connecting as a client
####################################################################################################

# Connect to the server using TCP (telnet)
tcp:
    telnet {{ server-addr }} {{ server-port }}

# Connect to the server using TCP (netcat)
tcp-nc:
    nc -Nnv {{ server-addr }} {{ server-port }}

# Connect to the server using UDP
udp:
    -nc -nu {{ server-addr }} {{ server-port }}

# Connect to the server using ICMP
[continue]
icmp:
    ping {{ server-addr }}

####################################################################################################
# Observation and stress testing
####################################################################################################

# Capture and print TUN device traffic and save to PCAP
[arg('x', short, value='-x', help='Show hex and ASCII')]
[continue]
sniff x='': tun
    mkdir -p '{{ pcap-dir }}'
    {{ tshark-cmd }} -i {{ tun-name }} -w '{{ pcap-file }}' {{ x }}
    @echo 'Saved to {{ pcap-file }}'

# Read a PCAP file with TShark (defaults to the most recent)
[
    arg('pcap', short, long, help='Name of PCAP file to read'),
    arg('x', short, value='-x', help='Show hex and ASCII'),
    arg('V', short, value='-V', help='Show full packet dissection')
]
sniff-inspect pcap=`just most-recent-pcap` x='' V='':
    @if [ -z "{{ pcap }}" ]; then \
        echo 'No PCAP file to inspect' >&2; \
        exit 1; \
    fi

    {{ tshark-cmd }} -r '{{ pcap }}' {{ x }} {{ V }} | "${PAGER:-less}"

# Internal helper for the `sniff-inspect` recipe's default PCAP file path
[private]
most-recent-pcap:
    ls -t {{ pcap-dir / "*.pcap" }} | head -n 1

# Remove the `pcap` directory
sniff-clean:
    rm -rf '{{ pcap-dir }}'

# Time echoing a text file through the server using TCP and diff the reply against the original
[arg('input-file', short='f', long, help='File to send')]
text input-file=justfile():
    time nc -Nnv {{ server-addr }} {{ server-port }} \
        < '{{ input-file }}' > '/tmp/{{ project-name }}-text-out'

    if command -v delta >/dev/null 2>&1; then \
        delta --paging never '{{ input-file }}' '/tmp/{{ project-name }}-text-out'; \
    else \
        diff '{{ input-file }}' '/tmp/{{ project-name }}-text-out'; \
    fi

    @echo 'Echoed data matched input exactly'

# Time echoing a random binary blob through the server using TCP and verify identical output bytes
blob: blob-gen
    time nc -Nnv {{ server-addr }} {{ server-port }} \
        < '{{ blob-file }}' > '/tmp/{{ project-name }}-blob-out'

    cmp '{{ blob-file }}' '/tmp/{{ project-name }}-blob-out'
    @echo "$(wc -c < '{{ blob-file }}' | numfmt --to=iec) blob echo matched byte for byte"

# Generate the random binary blob if it doesn't already exist
[private]
blob-gen size='1M':
    @mkdir -p '{{ blob-dir }}'
    @if [ ! -f '{{ blob-file }}' ]; then \
        head -c {{ size }} /dev/urandom > '{{ blob-file }}'; \
        echo 'Generated {{ size }} blob at {{ blob-file }}'; \
    fi

# Remove the generated binary blob
blob-clean:
    rm -rf '{{ blob-dir }}'

# Add emulation of real-world networks to the TUN device (uses sudo)
[
    arg('delay', short, long),
    arg('loss', short, long),
    arg('corrupt', short, long),
    arg('duplicate', short='u', long),
    arg('reorder', short, long)
]
netem delay='1ms' loss='0%' corrupt='0%' duplicate='0%' reorder='0%': tun
    sudo tc qdisc replace dev {{ tun-name }} root netem \
        delay {{ delay }} 20ms 25% distribution paretonormal \
        loss random {{ loss }} 25% \
        corrupt {{ corrupt }} 25% \
        duplicate {{ duplicate }} 25% \
        reorder {{ reorder }} 25%

# Apply jittery delay but no impairment
netem-jitter: (netem '1ms' '0%' '0%' '0%' '0%')
# Apply typical WAN/cross-region conditions
netem-wan: (netem '75ms' '0.3%' '0%' '0%' '0.1%')
# Apply poor mobile/Wi-Fi conditions
netem-mobile: (netem '150ms' '2%' '0.1%' '1%' '1%')
# Apply extreme conditions to stress test correctness
netem-abuse: (netem '100ms' '20%' '3%' '15%' '15%')

# Show current network emulation and packet counters
netem-show:
    tc -stats qdisc show dev {{ tun-name }}

# Remove emulated network conditions (uses sudo)
netem-clear:
    sudo tc qdisc del dev {{ tun-name }} root

####################################################################################################
# Testing and quality
####################################################################################################

# Run tests, lints, format checking, and spell checking to match CI
ci-checks: (test '--quiet') lint fmt-check spell-check

# Run tests, including ignored
test *ARGS: tun
    cargo test --workspace --all-targets --all-features {{ ARGS }} -- --include-ignored

# Generate test coverage report and print summary (includes ignored tests)
cov *ARGS: tun
    cargo llvm-cov {{ ARGS }} -- --include-ignored

# Generate HTML test coverage report (in `target/llvm-cov/html`) and open in browser
cov-open: (cov '--open')

# Run benchmarks (generates HTML in `target/criterion`)
bench:
    cargo bench --features bench-internals

# Lint with Clippy, denying warnings
lint:
    cargo clippy --workspace --all-targets --all-features -- --deny warnings

# Check formatting
fmt-check:
    RUSTUP_TOOLCHAIN=nightly cargo fmt --all --check && echo 'Formatting check passed'

# Apply formatting changes
fmt:
    RUSTUP_TOOLCHAIN=nightly cargo fmt --all

# Check spelling with Codebook
spell-check:
    git ls-files -z | xargs -0 codebook-lsp lint
