// if private data.json exists, exit with error, warn the user to delete old one before trying again
import { writeFileSync } from 'fs'
import {
  AuthenticationTransaction, Address,
  HD, Keyring, MTX, Output, Script, Utils } from 'bitauth'
import * as chalk from 'chalk'
import * as request from 'request'
import { config } from './config'
import { getMasterKey, getFundingAddress, getFundingKey,
  getIdentityBranch, getSigningBranch, getAddress, getKey } from './keys'

let master = getMasterKey()

interface InsightUTXO {
  address: string,
  txid: string,
  vout: number,
  scriptPubKey: string,
  amount: number,
  satoshis: number,
  height: number,
  confirmations: number
}

let fundingAddress = getFundingAddress(master)
request(
  {
    url: `https://test-insight.bitpay.com/api/addrs/${fundingAddress}/utxo/`,
    json: true
  },
  (err, res, utxos: InsightUTXO[]) => {
    if (err) {
      console.error(err)
      process.exit(1)
    }

    let authtx = new AuthenticationTransaction()
    authtx.setFeeRate(config.feeSatoshisPerByte)

    // if previous authhead is available, try
    if (config.addCoinsFromPreviousIndex) {
      console.error('TODO - addCoinsFromPreviousIndex not yet implemented')
      process.exit(1)
    }

    // add all available funding inputs
    utxos.forEach((utxo) => {
      if (typeof utxo.txid !== 'string' || typeof utxo.vout !== 'number' || typeof utxo.amount !== 'number') {
        console.error('Insight returned an unexpected value:')
        console.log(utxos)
        process.exit(1)
      }
      let coin = {
        height: utxo.height,
        value: utxo.satoshis,
        script: Script.fromRaw(utxo.scriptPubKey, 'hex'),
        // insight returns big-endian, we need little-endian
        hash: Utils.util.revHex(utxo.txid),
        index: utxo.vout
      }
      authtx.addCoin(coin)
    })

    // add the change output
    authtx.setChangeOutput(getFundingAddress(master))

    // add the identity output
    let identityAddress = getAddress(master, getIdentityBranch())
    authtx.setIdentityOutput(identityAddress, config.identitySatoshis)

    // add the signing output
    let signingAddress = getAddress(master, getSigningBranch())
    authtx.setSigningOutput(signingAddress, config.signingSatoshis)

    let fundingKey = getFundingKey(master)
    let keyring = new Keyring(fundingKey.privateKey, fundingKey.network)
    authtx.sign(keyring).then(() => {
      let txJson = authtx.toJSON()
      let txRaw = authtx.toRaw()
      let txRawHex = txRaw.toString('hex')

      console.log(chalk.inverse(`An Authentication Transaction was successfully created.`))
      console.log()
      console.log(`Transaction details:`)
      console.log(JSON.stringify(txJson, null, 2))
      console.log()

      writeFileSync(config.authtxPath, txRawHex)

      if (!authtx.isValid()) {
        console.error(chalk.red(`The generated Authentication Transaction is invalid due to an unexpected error.`))
        console.log(chalk.red(`Please report this as a bug: https://github.com/bitjson/bitauth/issues`))
      }
    })
})
