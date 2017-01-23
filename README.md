# BitAuth2017

Monorepo for the BitAuth2017 protocol standard. [(full specification)](/bips/0-bitauth.mediawiki)

### Get Involved
- [BitAuth on Twitter](https://twitter.com/bitauth)
- [BitAuth Slack Group](https://slack.bitauth.bitjson.com/)
- [BitAuth Reddit](https://www.reddit.com/r/BitAuth/)
- [BitAuth Issue Tracker](https://github.com/bitjson/bitauth2017/issues)

### Watch the Presentation

(Link will go here when it's available.)
The [BitAuth presentation slides](https://bitauth.bitjson.com/) are also available.

### Try the Demo CLI

Check out the [Demo Readme](demo/readme.md) to get started.

### Use the Library

An alpha version of the library is available for Node v6 and above (as well as Typescript typings).

```
git clone https://github.com/bitjson/bitauth.git
cd lib && yarn
yarn link
```

See the [readme](lib/readme.md) for details.

## Similar Projects

Please note, there have been a number of other projects which apply concepts in bitcoin for identity and authentication purposes.

My hope is that [BitPay's BitAuth](https://github.com/bitpay/bitauth) Node.js project will be deprecated in favor of the [`@bitjson/passport-bitauth`](passport-bitauth) module in this one, and that the infrastructure work in the following projects will migrate to the identity construction and authentication strategy utilized by this one:

- [AirBitz Edge Security](https://airbitz.co/developer-api-library/) - a single-signon security platform for blockchain apps
- [BitID](https://github.com/bitid/bitid) – very well-developed set of infrastructure for authentication. Bitcoin-like public/private keypair.
- [BitPay's BitAuth](https://github.com/bitpay/bitauth) – a Node.js implementation of Jeff Garzik's [Identity Protocol v1](https://en.bitcoin.it/wiki/Identity_protocol_v1). Bitcoin-like public/private keypair.
- [BlockAuth](http://blockauth.org/) - Decentralized Identity & Authentication by Neuroware
- [BlockchainID (old)](https://github.com/okTurtles/blockchainid) – Decentralized alternative to Facebook Login and OpenID
- [Blockstack Blockchain ID](https://github.com/blockstack/blockchain-id/wiki) – a unique identifier that is secured by a blockchain
- [Blockstack Auth JS](https://github.com/blockstack/blockstack-auth-js) - Blockstack Auth library, written in node.js
- [identity-on-bitcoin](https://github.com/domschiener/identity-on-bitcoin) - create identities, anchor them into the Bitcoin Blockchain, and authorize service providers to access specific attributes
