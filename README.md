## Secret Santa solver using Z3

This script generates secret santa assignments for a group of people and supports individualized constraints.
It prints the output encrypted with a password to avoid spoilers; providing the password allows reading the assignments.

Usage:
```
    python santa.py gen cfg.toml
    python santa.py dec <cfg.toml|password string> [name]
```

cfg.toml should have a "santa" table with "password" and "people" fields.
The people field should be a list of tables, where each entry has fields "name" and "conflict", where "conflict" is a list of names that person should not be assigned.

This script requires that openssl is installed.

Example config:
```toml
[santa]
password = "sleighbells"

[[santa.people]]
name = "alice"
conflict = ["eve"]

[[santa.people]]
name = "bob"
conflict = ["alice"]

[[santa.people]]
name = "charlie"
conflict = ["alice"]

[[santa.people]]
name = "eve"
conflict = []
```
