import {
  Coin,
  CoinView,
  Keyring,
  Output,
  TX,
  MTX,
  Script
} from './index'

export interface SigningOutput {
  hash: string,
  index: number,
  script: string
}

// use the maximum number of satoshis, just to be safe
const UNREASONABLE_NUMBER_OF_SATOSHIS = 2.1e15
// largest sequential factor of ^. Need better logic to support more signing identities.
const MAX_SIGNING_IDENTITIES = 8

/**
 * Create a BitAuth Signature Transaction (a.k.a. BitAuth Signature) – a bitcoin
 * transaction which spends the Signing Output of an Authentication Transaction
 * to a Digest Output – an unspendable output containing the digest of a message.
 *
 * BitAuth Signature Transactions are validated as standard bitcoin transactions,
 * except the input values do not need to exceed the output values. By setting
 * the Digest Output to a value greater than the transactions inputs, signers
 * can prevent the transaction from being accepted and mined on the blockchain.
 */
export class SignatureTransaction {
  private signingCoins: any[] = []
  private digestScript: any
  private mtx: any

  static verifySignature(signature: string | Buffer, signingOutputs: SigningOutput | SigningOutput[]) {
    let sigtx = typeof signature === 'string' ? TX.fromRaw(signature, 'hex') : TX.fromRaw(signature)
    let outputs = Array.isArray(signingOutputs) ? signingOutputs : [signingOutputs]
    let view = new CoinView()
    outputs.forEach((out) => {
      let next = new Output({
        script: Script.fromJSON(out.script),
        value: UNREASONABLE_NUMBER_OF_SATOSHIS / outputs.length
      })
      view.addOutput(out.hash, out.index, next)
    })
    return sigtx.verify(view) as boolean
  }

  static getDigestOutputInfo(signature: string | Buffer) {
    let sigtx = typeof signature === 'string' ? TX.fromRaw(signature, 'hex') : TX.fromRaw(signature)
    if (sigtx.outputs.length === 0) {
      return false
    }
    let digestScript = sigtx.outputs[0].script
    if (!digestScript.isNulldata()) {
      return false
    }
    let outputBuffer: string = digestScript.get(1).toString('hex')
    let algorithm = new Buffer(outputBuffer.slice(0, outputBuffer.indexOf('00')), 'hex').toString()
    return {
      algorithm: algorithm,
      messageDigest: outputBuffer.slice(outputBuffer.indexOf('00') + 2)
    }
  }

  addSigningOutput(authheadSigningOutput: SigningOutput) {
    this.signingCoins.push(new Coin({
      value: UNREASONABLE_NUMBER_OF_SATOSHIS,
      script: Script.fromJSON(authheadSigningOutput.script),
      index: authheadSigningOutput.index,
      hash: authheadSigningOutput.hash
    }))
  }

  setMessageDigest(algorithm: string, message: Buffer) {
    let digestScript = new Script()
    if (!(message instanceof Buffer)) {
      throw new Error('Message must be a buffer.')
    }
    digestScript.push(Script.opcodes.OP_RETURN)
    switch (algorithm) {
      case 'hash256':
      case 'hash160':
      case 'sha256':
      case 'ripemd160':
      case 'sha1':
        // mark the end of algorithm specification with UTF8 NUL
        let pushdata = Buffer.concat([new Buffer(algorithm + '\u0000'), message])
        digestScript.push(pushdata)
        break
      default:
        throw new Error('Unrecognized algorithm identifier.')
    }
    this.digestScript = digestScript.compile()
  }

  sign (keyring: any) {
    if (this.signingCoins.length === 0) {
      throw new Error('A Signing Output must be set before signing.')
    }
    if (typeof this.digestScript === 'undefined') {
      throw new Error('A message digest must be set before signing.')
    }
    let mtx = new MTX()
    mtx.addOutput({
      script: this.digestScript,
      value: UNREASONABLE_NUMBER_OF_SATOSHIS
    })
    if (this.signingCoins.length > MAX_SIGNING_IDENTITIES) {
      // the math gets complex
      throw new Error(`Signing a message with more than ${MAX_SIGNING_IDENTITIES} identities is not supported.`)
    }
    this.signingCoins.forEach((coin) => {
      coin.value = UNREASONABLE_NUMBER_OF_SATOSHIS / this.signingCoins.length
      mtx.addCoin(coin)
    })
    let ring = new Keyring(keyring)
    mtx.sign(ring)
    this.mtx = mtx
  }

  getDigestScriptHex () {
    return this.digestScript.toJSON()
  }

  getDigestScriptAssembly () {
    return this.digestScript.toASM()
  }

  isValid() {
    return this.mtx.verify()
  }

  toJSON(network: 'testnet' | 'main' = 'main') {
    return this.mtx.getJSON(network)
  }

  toRaw() {
    return this.mtx.toTX().toRaw()
  }
}
