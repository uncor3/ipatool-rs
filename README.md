Download IPAs directly from Apple, a port of ipatool by @majd to pure Rust

```shell
Usage: ipatool-rs <COMMAND>

Commands:
  auth
  search
  purchase
  download
  list-versions
  get-version-metadata
  help                  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help (see more with '--help')
  -V, --version  Print version

```

It will default to cli feature so use it like this if you want to use it as a library:

```toml
[dependencies]
ipatool = { version = "0.3.0", default-features = false }
```

Not affiliated with Apple
