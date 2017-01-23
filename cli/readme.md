# bitauth-cli

** Not ready yet. See [the spec](spec.md) for a preview. **


This utility verifies the authenticity of BitAuth signed files using a built-in SPV bitcoin client.

Usage:

```bash
$ bitauth FILENAME
```

This utility stores headers-only copies of the mainnet blockchain at `~/.bitauth/data/main` and testnet blockchain at `~/.bitauth/data/testnet`. To verify a file, the utility must SPV sync with the bitcoin network to at least the block height required by the authenticated file.
