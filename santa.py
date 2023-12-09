"""Secret Santa solver using Z3

This script generates secret santa assignments for a group of people and supports individualized constraints.
It prints the output encrypted with a password to avoid spoilers; providing the password allows reading the assignments.

Usage:
    python santa.py gen cfg.toml
    python santa.py dec <cfg.toml|password string> [name]

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
"""

from z3 import EnumSort, Consts, Solver, Not, And
import toml
from random import choice
import subprocess as sh
import sys

def generate(cfg):
    password = cfg['santa']['password']
    names = [p['name'] for p in cfg['santa']['people']]
    people = { p['name']:p for p in cfg['santa']['people']}

    s = Solver()
    Person, z3people = EnumSort('assignment', names)
    z3people = { str(p):p for p in list(z3people) }
    people_slots = Consts(' '.join(names), Person)
    for slot, p in zip(people_slots, z3people):
        s.add(slot != z3people[p])
    for slot in people_slots:
        for slot1 in people_slots:
            if str(slot) != str(slot1):
                s.add(slot != slot1)

    people_slots_ref = { str(p) : (people[str(p)], p) for p in people_slots }
    for n in people_slots_ref:
        d, slot = people_slots_ref[n]
        for c in d['conflict']:
            s.add(slot != z3people[c])

    possibilities = []
    while str(s.check()) == 'sat':
        model = s.model()
        possibilities.append(model)
        s.add(Not(And(*[p == model[p] for p in people_slots])))

    if len(possibilities) == 0:
        raise Exception("there were no satisfying assignments")

    assignment = choice(possibilities)

    ret = []
    for p in people_slots:
        recipient = assignment[p]
        out = sh.run(f"echo {recipient} | openssl bf -a -salt -pbkdf2 -provider legacy -provider default -k '{password}' -e", shell=True, capture_output=True).stdout
        out = out.decode('utf-8').strip()
        ret.append((p, out))
    return ret

def decode(cipher, password):
    out = sh.run(f"echo {cipher} | openssl bf -a -salt -pbkdf2 -provider legacy -provider default -k '{password}' -d", shell=True, capture_output=True).stdout
    out = out.decode('utf-8').strip()
    if len(out) == 0:
        raise Exception("error decoding code")
    return out

if __name__ == '__main__':
    if sys.argv[1].lower().startswith('gen'):
        cfg = toml.load(sys.argv[2])
        assignment = generate(cfg)
        for a, code in assignment:
            print(a, code)
    elif sys.argv[1].lower().startswith('dec'):
        coded = [l.strip().split() for l in sys.stdin]
        password = sys.argv[2]
        if 'toml' in sys.argv[2]:
            cfg = toml.load(sys.argv[2])
            password = cfg['santa']['password']
        filt = None
        if len(sys.argv) > 3:
            filt = sys.argv[3]
        for name, cipher in coded:
            if name == filt or filt == None:
                print(name, decode(cipher, password))
