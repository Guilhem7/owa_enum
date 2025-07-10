# Enum OWA
Try to enumerate valid usernames on an **OWA** with **Forms-based**.

## Install
```sh
# Build the project
# If using mise: mise use -g rust@latest
cargo build --release
./target/release/owa_enum -h
```

## Usage
```sh
# Test to check valid a single valid user
cargo run -- --target THE-EYRIE.sevenkingdoms.local --user lysa.arryn

# Test multiple users and write output to a file
cargo run -- --target THE-EYRIE.sevenkingdoms.local --user users.txt --domain SEVENKINGDOMS --output valid_users.txt --password 'test123!'

```

```sh
cargo run -- -h

Usage: owa_enum [OPTIONS] --target <TARGET> --user <USER>

Options:
  -t, --target <TARGET>
          Target to attack
  -u, --user <USER>
          Username to check or file containing usernames
  -p, --password <PASSWORD>
          Password to use for authentication [default: Azerty@123]
  -d, --domain <DOMAIN>
          Target domain (optional) to connect with
      --timeout <TIMEOUT>
          Timeout to use for considering user does not exists [default: 3]
      --threads-number <THREADS_NUMBER>
          The number of thread to use [default: 4]
  -o, --output <OUTPUT>
          Output valid users to a file
  -h, --help
          Print helps
```
