import {
  Address,
  Coin,
  Keyring,
  Output,
  TX,
  MTX,
  Script
} from './index'

// https://github.com/bitcoin/bitcoin/blob/0.13/src/primitives/transaction.h#L165
const NETWORK_MINIMUM_OUTPUT_SATOSHIS = 546

/**
 * Create a BitAuth Authentication Transaction – a valid bitcoin transaction
 * (usually on-chain) which can serve as the basis for a BitAuth Identity.
 */
export class AuthenticationTransaction {
  // TODO: these should all be type-checked (such that this file has no `any` types)
  private network: any
  private coins: any[] = []
  private identityOutput: any
  private signingOutput: any
  // all remaining satoshis are sent to the changeOutput, so this output has no defined value
  private changeAddress: any
  private otherOutputs: any[] = []
  private feeSatoshisPerKb: number
  private mtx: any

  addCoin(coin: any) {
    this.coins.push(new Coin(coin))
  }

  addOutput(output: any) {
    this.otherOutputs.push(new Output(output))
  }

  setFeeRate (satoshisPerByte: number) {
    this.feeSatoshisPerKb = satoshisPerByte * 1000
  }

  setIdentityOutput(address: any, satoshis: number = NETWORK_MINIMUM_OUTPUT_SATOSHIS) {
    let addr = new Address(address)
    this.network = addr.network
    this.identityOutput = new Output({
      address: addr,
      value: satoshis
    })
  }

  setSigningOutput(address: any, satoshis: number = NETWORK_MINIMUM_OUTPUT_SATOSHIS) {
    this.signingOutput = new Output({
      address: new Address(address),
      value: satoshis
    })
  }

  setChangeOutput(address: any) {
    this.changeAddress = new Address(address)
  }

  sign (keyring: any) {
    if (typeof this.identityOutput === 'undefined') {
      throw new Error('An identityOutput must be set before signing an AuthenticationTransaction.')
    }
    if (typeof this.feeSatoshisPerKb === 'undefined') {
      throw new Error('A fee rate must be set before signing an AuthenticationTransaction.')
    }
    if (typeof this.changeAddress === 'undefined') {
      throw new Error('A changeOutput must be set before signing an AuthenticationTransaction.')
    }
    let mtx = new MTX()
    mtx.addOutput(this.identityOutput)
    if (typeof this.signingOutput !== 'undefined') {
      mtx.addOutput(this.signingOutput)
    }
    this.otherOutputs.forEach((output) => {
      mtx.addOutput(output)
    })
    return mtx.fund(this.coins, {
      rate: this.feeSatoshisPerKb,
      changeAddress: this.changeAddress
    }).then(() => {
      let ring = new Keyring(keyring)
      mtx.sign(ring)
      this.mtx = mtx
    })
  }

  isValid() {
    return this.mtx.verify()
  }

  toTX() {
    return this.mtx.toTX()
  }

  toJSON() {
    return this.mtx.getJSON(this.network)
  }

  toRaw() {
    return this.mtx.toTX().toRaw()
  }
}
