# Fingerprunk

**Fingerprunk** (/ˈfɪŋɐpʁʊŋk/; from *fingerprint* and German *Prunk* 'pageantry, splendor') is
a CLI tool for brute-forcing OpenPGP keys with fingerprints that match a given regex.

## Installation

Install [Rust](https://rust-lang.org/tools/install/), then install Fingerprunk from crates.io:

```sh
cargo install fingerprunk
```

## Usage

Let's say you want to find keys whose fingerprints begin with `C0FFEE` and store them `secret.asc`.
The regex for this is `^C0FFEE`. Now, simply use the following command to start the search:

```sh
fingerprunk -r '^C0FFEE' >> secret.asc
```

Fingerprunk will now generate many keys and write out all keys with matching fingerprints to
standard output (here: `secret.asc`).

If you want Fingerprunk to output password-encrypted keys use the `-p` flag and you will be prompted
for a password.

### Regex format

Fingerprunk uses [fancy-regex](https://crates.io/crates/fancy-regex), for which you can test and
debug your regexes at the [fancy-regex playground](https://fancy-regex.github.io/fancy-regex/).

The regex is matched against the upper-case hexadecimal representation of the fingerprint, e.g.
`C0FFEE2494E2B365CAB564236C79CDD8F048CBDC`.

Here is some inspiration for regexes you could use:

| Regex          | Description                              |
| :------------  | :--------------------------------------- |
| `^C0FFEE`      | String `C0FFEE` at the beginning         |
| `0FF1CE$`      | String `0FF1CE` at the end               |
| `(.)\1{7}`     | A string of eight identical characters   |
| `^(....)*FFFF` | String `FFFF` aligned to a 4-digit group |

Be sure to escape your regex in your shell, e.g. `'(.)\\1{7}'` instead of `'(.)\1{7}'`.

Also see <https://en.wikipedia.org/wiki/Hexspeak> for some further examples of "hexadecimal words".

### How long does it take?

On my machine with an AMD Ryzen 7 5800X Processor, Fingerprunk is able to generate and check about
43300 keys per second. This means that for finding a fingerprint with a string of *n* specific
hexadecimal digits at a specific place, I could expect the following runtimes until finding the
first key:

| *n* |  expected tries | expected time |
| --: | --------------: | ------------: |
| *n* |             16ⁿ |  43300s / 16ⁿ |
|   2 |             256 |   0.0059 secs |
|   3 |            4096 |   0.0946 secs |
|   4 |           65536 |      1.5 secs |
|   5 |         1028576 |       24 secs |
|   6 |        16777216 |      6.5 mins |
|   7 |       268435456 |      103 mins |
|   8 |      4294967296 |      27 hours |
|   9 |     68719476736 |       18 days |
|  10 |   1099511627776 |      293 days |
|  11 |  17592186044416 |      13 years |
|  12 | 281474976710656 |     206 years |

As you can see, anything above 8 or 9 fixed digits is pretty much unfeasible, at least with
a normal personal computer.