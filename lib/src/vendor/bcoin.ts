/// <reference path="bcoin.d.ts" />
import * as bcoin from 'bcoin'

const Address = bcoin.address
const Amount = bcoin.amount
const Coin = bcoin.coin
const CoinView = bcoin.coinview
const Crypto = bcoin.crypto
const HD = bcoin.hd
const Input = bcoin.input
const Keyring = bcoin.keyring
const MTX = bcoin.mtx
const TX = bcoin.tx
const Outpoint = bcoin.outpoint
const Output = bcoin.output
const Script = bcoin.script
const Utils = bcoin.utils

export {
  bcoin,
  Address,
  Amount,
  Coin,
  CoinView,
  Crypto,
  HD,
  Input,
  Keyring,
  MTX,
  Outpoint,
  Output,
  Script,
  TX,
  Utils
}
