# BitAuth Demo

This is a highly-simplified demo of message signing using a testnet BitAuth identity.

## Getting Started

You'll need to have [Node](https://nodejs.org/) (v6 or later) and [Yarn](https://yarnpkg.com/en/docs/install) installed. To build the demo, clone this repo and install the dependencies with the following commands:

```bash
git clone https://github.com/bitjson/bitauth.git
cd bitauth/demo
yarn
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

## Step 4 – Sign a Message

With your identity ready, you can sign a message. You can modify `message.txt` if you'd like, then run:

```bash
yarn sign
```

This will sign the contents of `message.txt` and output `signature.bitauthsig`

## Step 5 – Verify the Signature

To verify the signature, run:
```bash
yarn verify
```

This will validate that your identity properly signed the exact contents of `message.txt`.
