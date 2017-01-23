import { TX } from './index'

/**
 * A read-only instance
 */
export class Authhead {
  private tx: any

  constructor(tx: any, enc?: string) {
    this.tx = TX.fromRaw(tx, enc)
  }

  getSigningOutput() {
    // we don't use addresses here, so main network addresses are fine
    let obj = this.toObject('main')
    // if the authhead has only one output, it is also the signing output
    let signingIndex = obj.outputs.length > 1 ? 1 : 0
    return {
      hash: this.getHash(),
      index: signingIndex as number,
      script: obj.outputs[signingIndex].script as string
    }
  }

  getId() {
    return this.getHash()
  }

  getHash() {
    return this.tx.toJSON().hash as string
  }

  toObject(network: string) {
    return this.tx.getJSON(network)
  }
}
