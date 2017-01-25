import { Crypto } from './index'

/**
 * Convenience class to provide message digest and verification functionality.
 */
export class Message {
  private message: Buffer

  constructor (message: string | Buffer) {
    if (typeof message === 'string') {
      this.message = new Buffer(message)
    } else if (message instanceof Buffer) {
     this.message = message
   } else {
     throw new Error('Invalid message type provided to Message constructor.')
   }
  }

  toBuffer() {
    return this.message
  }

  toHex() {
    return this.message.toString('hex')
  }

  toString() {
    return this.message.toString()
  }

  getDigest(algorithm: string) {
    if (typeof algorithm !== 'string') {
      throw new Error('Algorithm identifier must be a string.')
    }
    switch (algorithm) {
      case 'hash256':
        return Crypto.hash256(this.message) as Buffer
      case 'hash160':
        return Crypto.hash160(this.message) as Buffer
      case 'sha256':
        return Crypto.sha256(this.message) as Buffer
      case 'ripemd160':
        return Crypto.ripemd160(this.message) as Buffer
      case 'sha1':
        return Crypto.sha1(this.message) as Buffer
      default:
        throw new Error('Unrecognized algorithm identifier.')
    }
  }
}
