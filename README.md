# Enum OWA
Try to enumerate valid usernames on an **OWA** with **Forms-based**.

## Usage
```sh
# Test to check valid users from file users.txt
cargo run -- --target test.contoso.fr --user users.txt

# Test multiple users and write output to a file
cargo run -- --target test.contoso.fr --user users.txt --domain TEST.CONTOSO.LOCAL --output valid_users.txt --password 'test123!'

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
