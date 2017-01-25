# BitAuth2017

Monorepo for the BitAuth2017 protocol standard. [(full specification)](/bips/0-bitauth.mediawiki)

### Get Involved
- [BitAuth on Twitter](https://twitter.com/bitauth)
- [BitAuth Slack Group](https://bitauthtalk.bitjson.com/)
- [BitAuth Reddit](https://www.reddit.com/r/BitAuth/)
- [BitAuth Issue Tracker](https://github.com/bitjson/bitauth/issues)

### Watch the Presentation

(Link will go here when it's available.)
The [BitAuth presentation slides](https://bitauth.bitjson.com/) are also available.

### Try the Demo CLI

This is a highly-simplified demo of message signing using a testnet BitAuth identity.

## Getting Started

You'll need to have [Node](https://nodejs.org/) (v6 or later) and [Yarn](https://yarnpkg.com/en/docs/install) installed. To build the demo, clone this repo and install the dependencies with the following commands:

```bash
git clone https://github.com/bitjson/bitauth2017.git
cd bitauth2017/lib && yarn && yarn link
cd ../demo && yarn && yarn link bitauth
```

## Step 1 – Generate Key & Address

Generate a new HD key for our testing by running:

```bash
yarn genkey
```

This will generate the file: `data/private.json`, and output a new testnet address.

## Step 2 – Fund the Address

Paste your testnet address into a [testnet bitcoin faucet](https://testnet.manu.backend.hamburg/faucet), and send some funds.

## Step 3 – Create a Testnet BitAuth Identity

Once the funds have been sent, create your BitAuth Identity by running:

```bash
yarn genid
```

This command will fetch all UTXOs sent to your address, create a new Authentication Transaction (authtx) at `data/authbase.bitcointx`, and broadcast the transaction to the testnet.

This transaction will serve as the authbase of your testnet identity. It's currently single-signature, but can be upgraded to more complex authentication requirements with additional authtxs.

If everything looks good, you can broadcast the transaction by running:
```bash
yarn broadcast
```

Your transaction will look something like [6213455da06d44842cde9b1b271aa186e6ec0b2b3b2df82a55aa54da756339d4](https://test-insight.bitpay.com/tx/6213455da06d44842cde9b1b271aa186e6ec0b2b3b2df82a55aa54da756339d4).

```hex
01000000014298e0e9f1fa4aad63b25a701095b937150be03c9304a86dd846a098a48dd8dd000000006a473044022078cc85f6d83fea8961a6afa8f1b524a5fd618526c9f98c63b00d3fb1d3f4008a0220248bb35fb12c46349f6c94aa224db16d32ecbb75e6ea8819116268261cfb78cc012103c8a2dc1bbbb5e261abcdc89c03384c2b80330b84a52694725cd53d28aeb0f56fffffffff03405dc600000000001976a914cf7e9df9c834338aa1b310b288e2d91cf459c74388ac405dc600000000001976a914a1a767a9b17fdd3ee0f841568a369fd56d1fc5e288acfe318e0a000000001976a914ac19d3fd17710e6b9a331022fe92c693fdf6659588ac00000000
```

## Step 4 – Sign a Message

With your identity ready, you can sign a message. You can modify `message.txt` if you'd like, then run:

```bash
yarn sign
```

This will sign the contents of `message.txt` and output `signature.bitauthsig`

Example using the authbase above:

```hex
01000000016213455da06d44842cde9b1b271aa186e6ec0b2b3b2df82a55aa54da756339d4010000006b483045022100a152595d0d0a74b18e1c528bc5da0500c98b2ab35d5c57034227b6232e9b889302202888b281e13a3a623d0f24c108685ffe30a67903d1b3e3d04c5effd741a977fe012102a9e7d0b9d3dd050105140986901ddfbdf3398e14d9f906d4076af3cc2af32b3effffffff010040075af07507002a6a286861736832353600fc75eaa433dac149fd2ed5304f98e1542ce16a77fbb57a91fd489d87d2bc0a8500000000
```

## Step 5 – Verify the Signature

To verify the signature, run:
```bash
yarn verify
```

This will validate that your identity properly signed the exact contents of `message.txt`.

```bash
$ node build/verify.js
Verifying the signature transaction, given authhead: 6213455da06d44842cde9b1b271aa186e6ec0b2b3b2df82a55aa54da756339d4

✔ Signature transaction is valid.

Verifying the message digest is correct:
Message as string:
Hello, BitAuth!

Message as hex:
48656c6c6f2c2042697441757468210a
Message digest using algorithm hash256:
fc75eaa433dac149fd2ed5304f98e1542ce16a77fbb57a91fd489d87d2bc0a85

Signature transaction digest info:
algorithm: hash256
message digest: fc75eaa433dac149fd2ed5304f98e1542ce16a77fbb57a91fd489d87d2bc0a85

✔ Message digest matches.

✨  Done in 0.37s.
```

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
- [Certcoin](https://github.com/cfromknecht/certcoin) - A Decentralized PKI for Highly-Available Hierarchical Identities
- [identity-on-bitcoin](https://github.com/domschiener/identity-on-bitcoin) - create identities, anchor them into the Bitcoin Blockchain, and authorize service providers to access specific attributes
