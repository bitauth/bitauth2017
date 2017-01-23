// Note: this is a rough and incomplete definition. Only properties and methods used by this
// library are included below. In many cases, constructors have not been fully described.

declare module 'bcoin' {

  // type BitcoinNetworkType = 'main' | 'testnet' | 'regtest' | 'segnet4' | 'simnet'

  declare const address: AddressConstructor
  declare const amount: AmountConstructor
  declare const coin: CoinConstructor
  declare const coinview: CoinViewConstructor
  declare const hd: HD
  declare const input: InputConstructor
  declare const keyring: KeyringConstructor
  declare const mtx: MtxConstructor
  declare const outpoint: OutpointConstructor
  declare const output: OutputConstructor
  declare const script: ScriptConstructor
  declare const tx: TxConstructor
  declare const utils: Utils

  export interface AddressConstructor {
    types: {
        PUBKEYHASH: number
        SCRIPTHASH: number
        WITNESSPUBKEYHASH: number
        WITNESSSCRIPTHASH: number
    }
    new (options: any): Address
    fromBase58(address: any): any
    fromHash(hash: any, type: any, version: any, network: any): any
    fromInputScript(script: any): any
    fromOptions(options: any): any
    fromProgram(version: any, hash: any, network: any): any
    fromPubkeyhash(hash: any, network: any): any
    fromRaw(data: any): any
    fromScript(script: any): any
    fromScripthash(hash: any, network: any): any
    fromWitness(witness: any): any
    fromWitnessPubkeyhash(hash: any, network: any): any
    fromWitnessScripthash(hash: any, network: any): any
    getHash(data: any, enc: any): any
    getPrefix(type: any, network: any): any
    getType(prefix: any, network: any): any
    isWitness(type: any): any
  }
  export interface Address {
    hash: any
    network: any
    type: any
    version: any
    fromBase58(data: any): any
    fromHash(hash: any, type: any, version: any, network: any): any
    fromInputScript(script: any): any
    fromOptions(options: any): any
    fromProgram(version: any, hash: any, network: any): any
    fromPubkeyhash(hash: any, network: any): any
    fromRaw(data: any): any
    fromScript(script: any): any
    fromScripthash(hash: any, network: any): any
    fromWitness(witness: any): any
    fromWitnessPubkeyhash(hash: any, network: any): any
    fromWitnessScripthash(hash: any, network: any): any
    getHash(enc: any): any
    getPrefix(network: any): any
    getSize(): any
    getType(): any
    inspect(): any
    isProgram(): any
    isPubkeyhash(): any
    isScripthash(): any
    isWitnessMasthash(): any
    isWitnessPubkeyhash(): any
    isWitnessScripthash(): any
    toBase58(network: any): any
    toRaw(network: any): any
    toString(): any
    verifyNetwork(network: any): any
  }

  export interface AmountConstructor {
    new (value: any, unit?: any, num?: any): Amount
     btc(value: any, num: any): any
     from(unit: any, value: any, num: any): any
     fromBTC(value: any, num: any): any
     fromBits(value: any, num: any): any
     fromMBTC(value: any, num: any): any
     fromOptions(value: any, unit: any, num: any): any
     fromSatoshis(value: any, num: any): any
     fromValue(value: any): any
     parse(value: any, exp: any, num: any): any
     parseUnsafe(value: any, exp: any, num: any): any
     serialize(value: any, exp: any, num: any): any
     serializeUnsafe(value: any, exp: any, num: any): any
     value(value: any, num: any): any
  }
  export interface Amount {
    from(unit: any, value: any, num: any): any
    fromBTC(value: any, num: any): any
    fromBits(value: any, num: any): any
    fromMBTC(value: any, num: any): any
    fromOptions(value: any, unit: any, num: any): any
    fromSatoshis(value: any, num: any): any
    fromValue(value: any): any
    inspect(): any
    to(unit: any, num: any): any
    toBTC(num: any): any
    toBits(num: any): any
    toMBTC(num: any): any
    toSatoshis(num?: any): any
    toString(): any
    toValue(): any
  }

  export interface CoinConstructor {
    new (options: any): Coin
    fromJSON(json: any): any
    fromKey(key: any): any
    fromOptions(options: any): any
    fromRaw(data: any, enc: any): any
    fromReader(br: any): any
    fromTX(tx: any, index: any, height: any): any
    isCoin(obj: any): any
  }
  export interface Coin {
    fromJSON(json: any): any
    fromKey(key: any): any
    fromOptions(options: any): any
    fromRaw(data: any): any
    fromReader(br: any): any
    fromTX(tx: any, index: any, height: any): any
    getDepth(height: any): any
    getJSON(network: any, minimal: any): any
    getSize(): any
    inspect(): any
    toJSON(): any
    toKey(): any
    toRaw(): any
    toWriter(bw: any): any
  }

  export interface CoinViewConstructor {
    new (): CoinView
    fromFast(br: any, tx: any): any
    fromRaw(data: any, tx: any): any
    fromReader(br: any, tx: any): any
  }
  export class CoinView {
    add(coins: any): any
    addCoin(coin: any): void
    addOutput(hash: any, index: any, output: any): void
    addTX(tx: any, height: any): any
    ensureInputs(...args: any[]): any
    fromFast(br: any, tx: any): any
    fromReader(br: any, tx: any): any
    get(hash: any): any
    getCoin(input: any): any
    getEntry(input: any): any
    getFastSize(tx: any): any
    getHeight(input: any): any
    getOutput(input: any): any
    has(hash: any): any
    hasEntry(input: any): any
    isCoinbase(input: any): any
    readCoins(...args: any[]): any
    remove(hash: any): any
    removeOutput(hash: any, index: any): any
    removeTX(tx: any, height: any): any
    spendFrom(coins: any, index: any): any
    spendInputs(...args: any[]): any
    spendOutput(hash: any, index: any): any
    toArray(): any
    toFast(bw: any, tx: any): any
    toRaw(tx: any): any
    toWriter(bw: any, tx: any): any
  }

  export namespace crypto {
      class AEAD {
          constructor()
          aad(aad: any): void
          auth(data: any): any
          decrypt(data: any): any
          encrypt(data: any): any
          finish(): any
          init(key: any, iv: any): void
          pad16(size: any): void
      }
      class ChaCha20 {
          constructor()
          encrypt(data: any): any
          getCounter(): any
          init(key: any, iv: any, counter: any): void
          initIV(iv: any, counter: any): void
          initKey(key: any): void
          setCounter(counter: any): void
      }
      class Poly1305 {
          constructor()
          static auth(msg: any, key: any): any
          static verify(mac1: any, mac2: any): any
          blocks(data: any, bytes: any, m: any): void
          finish(): any
          init(key: any): void
          update(data: any): void

      }
      const pk: {
          dsa: {
              sign: any
              signAsync: any
              verify: any
              verifyAsync: any
          }
          ecdsa: {
              sign: any
              signAsync: any
              verify: any
              verifyAsync: any
          }
          rsa: {
              sign: any
              signAsync: any
              verify: any
              verifyAsync: any
          }
      }
      function ccmp(a: any, b: any): any
      function cleanse(data: any): void
      function createMerkleBranch(index: any, leaves: any): any
      function createMerkleRoot(leaves: any): any
      function createMerkleTree(leaves: any): any
      function decipher(data: any, key: any, iv: any): any
      function encipher(data: any, key: any, iv: any): any
      function hash(alg: any, data: any): any
      function hash160(data: any): any
      function hash256(data: any): any
      function hash256Async(...args: any[]): any
      function hashAsync(...args: any[]): any
      function hkdfExpand(prk: any, info: any, len: any, alg: any): any
      function hkdfExtract(ikm: any, key: any, alg: any): any
      function hmac(alg: any, data: any, key: any): any
      function hmacAsync(...args: any[]): any
      function pbkdf2(key: any, salt: any, iter: any, len: any, alg: any): any
      function pbkdf2Async(key: any, salt: any, iter: any, len: any, alg: any): any
      function randomBytes(): any
      function randomInt(): any
      function randomRange(min: any, max: any): any
      function ripemd160(data: any): any
      function scrypt(passwd: any, salt: any, N: any, r: any, p: any, len: any): any
      function scryptAsync(...args: any[]): any
      function sha1(data: any): any
      function sha256(data: any): any
      function siphash(data: any, key: any): any
      function siphash256(data: any, key: any): any
      function verifyMerkleBranch(hash: any, branch: any, index: any): any
      namespace chachapoly {
          class AEAD {
              constructor()
              aad(aad: any): void
              auth(data: any): any
              decrypt(data: any): any
              encrypt(data: any): any
              finish(): any
              init(key: any, iv: any): void
              pad16(size: any): void
          }
          class ChaCha20 {
              constructor()
              encrypt(data: any): any
              getCounter(): any
              init(key: any, iv: any, counter: any): void
              initIV(iv: any, counter: any): void
              initKey(key: any): void
              setCounter(counter: any): void
          }
          class Poly1305 {
              constructor()
              static auth(msg: any, key: any): any
              static verify(mac1: any, mac2: any): any
              blocks(data: any, bytes: any, m: any): void
              finish(): any
              init(key: any): void
              update(data: any): void
          }
      }
      namespace crypto {
          function ccmp(a: any, b: any): any
          function cleanse(data: any): void
          function createMerkleBranch(index: any, leaves: any): any
          function createMerkleRoot(leaves: any): any
          function createMerkleTree(leaves: any): any
          function decipher(data: any, key: any, iv: any): any
          function decipherAsync(...args: any[]): any
          function encipher(data: any, key: any, iv: any): any
          function encipherAsync(...args: any[]): any
          function hash(alg: any, data: any): any
          function hash160(data: any): any
          function hash256(data: any): any
          function hash256Async(...args: any[]): any
          function hashAsync(...args: any[]): any
          function hkdfExpand(prk: any, info: any, len: any, alg: any): any
          function hkdfExtract(ikm: any, key: any, alg: any): any
          function hmac(alg: any, data: any, key: any): any
          function hmacAsync(...args: any[]): any
          function pbkdf2(key: any, salt: any, iter: any, len: any, alg: any): any
          function pbkdf2Async(key: any, salt: any, iter: any, len: any, alg: any): any
          function randomBytes(): any
          function randomInt(): any
          function randomRange(min: any, max: any): any
          function ripemd160(data: any): any
          function scrypt(passwd: any, salt: any, N: any, r: any, p: any, len: any): any
          function scryptAsync(...args: any[]): any
          function sha1(data: any): any
          function sha256(data: any): any
          function verifyMerkleBranch(hash: any, branch: any, index: any): any
      }
      namespace dsa {
          function sign(alg: any, msg: any, key: any): any
          function signAsync(...args: any[]): any
          function verify(alg: any, msg: any, sig: any, key: any): any
          function verifyAsync(...args: any[]): any
      }
      namespace ec {
          function ecdh(pub: any, priv: any): any
          function fromDER(sig: any): any
          function generatePrivateKey(): any
          function isLowS(sig: any): any
          function privateKeyTweakAdd(privateKey: any, tweak: any): any
          function privateKeyVerify(key: any): any
          function publicKeyConvert(key: any, compressed: any): any
          function publicKeyCreate(priv: any, compressed: any): any
          function publicKeyTweakAdd(publicKey: any, tweak: any, compressed: any): any
          function publicKeyVerify(key: any): any
          function recover(msg: any, sig: any, j: any, compressed: any): any
          function sign(msg: any, key: any): any
          function toDER(sig: any): any
          function verify(msg: any, sig: any, key: any, historical: any, high: any): any
      }
      namespace ecdsa {
          function sign(curve: any, msg: any, alg: any, key: any): any
          function signAsync(...args: any[]): any
          function verify(curve: any, msg: any, alg: any, key: any, sig: any): any
          function verifyAsync(...args: any[]): any
      }
      namespace rsa {
          function sign(alg: any, msg: any, key: any, params: any): any
          function signAsync(...args: any[]): any
          function verify(alg: any, msg: any, sig: any, key: any, params: any): any
          function verifyAsync(...args: any[]): any
      }
      namespace schnorr {
          function combineKeys(keys: any): any
          function combineSigs(sigs: any): any
          function drbg(msg: any, priv: any, data: any): any
          function generateNoncePair(msg: any, priv: any, data: any, ncb: any): any
          function hash(msg: any, r: any, hash: any): any
          function nonce(msg: any, priv: any, data: any, ncb: any): any
          function partialSign(msg: any, priv: any, privnonce: any, pubs: any, hash: any): any
          function recover(signature: any, msg: any, hash: any): any
          function rfc6979(msg: any, priv: any, data: any): any
          function sign(msg: any, key: any, hash: any, pubnonce: any): any
          function verify(msg: any, signature: any, key: any, hash: any): any
          namespace alg {
              const BYTES_PER_ELEMENT: number
              const byteLength: number
              const byteOffset: number
              const length: number
              const offset: number
              function asciiSlice(): any
              function asciiWrite(): any
              function base64Slice(): any
              function base64Write(): any
              function compare(target: any, start: any, end: any, thisStart: any, thisEnd: any): any
              function copy(): any
              function copyWithin(p0: any, p1: any): any
              function entries(): any
              function equals(b: any): any
              function every(p0: any): any
              function fill(val: any, start: any, end: any, encoding: any): any
              function filter(p0: any): any
              function find(p0: any): any
              function findIndex(p0: any): any
              function forEach(p0: any): any
              function hexSlice(): any
              function hexWrite(): any
              function includes(val: any, byteOffset: any, encoding: any): any
              function indexOf(val: any, byteOffset: any, encoding: any): any
              function inspect(): any
              function join(p0: any): any
              function keys(): any
              function lastIndexOf(val: any, byteOffset: any, encoding: any): any
              function latin1Slice(): any
              function latin1Write(): any
              function map(p0: any): any
              function readDoubleBE(offset: any, noAssert: any): any
              function readDoubleLE(offset: any, noAssert: any): any
              function readFloatBE(offset: any, noAssert: any): any
              function readFloatLE(offset: any, noAssert: any): any
              function readInt16BE(offset: any, noAssert: any): any
              function readInt16LE(offset: any, noAssert: any): any
              function readInt32BE(offset: any, noAssert: any): any
              function readInt32LE(offset: any, noAssert: any): any
              function readInt8(offset: any, noAssert: any): any
              function readIntBE(offset: any, byteLength: any, noAssert: any): any
              function readIntLE(offset: any, byteLength: any, noAssert: any): any
              function readUInt16BE(offset: any, noAssert: any): any
              function readUInt16LE(offset: any, noAssert: any): any
              function readUInt32BE(offset: any, noAssert: any): any
              function readUInt32LE(offset: any, noAssert: any): any
              function readUInt8(offset: any, noAssert: any): any
              function readUIntBE(offset: any, byteLength: any, noAssert: any): any
              function readUIntLE(offset: any, byteLength: any, noAssert: any): any
              function reduce(p0: any): any
              function reduceRight(p0: any): any
              function reverse(): any
              function set(p0: any): any
              function slice(start: any, end: any): any
              function some(p0: any): any
              function sort(p0: any): any
              function subarray(p0: any, p1: any): any
              function swap16(): any
              function swap32(): any
              function swap64(): any
              function toJSON(): any
              function toLocaleString(): any
              function toString(...args: any[]): any
              function ucs2Slice(): any
              function ucs2Write(): any
              function undefined(): any
              function utf8Slice(): any
              function utf8Write(): any
              function values(): any
              function write(writeString: any, offset: any, length: any, encoding: any): any
              function writeDoubleBE(val: any, offset: any, noAssert: any): any
              function writeDoubleLE(val: any, offset: any, noAssert: any): any
              function writeFloatBE(val: any, offset: any, noAssert: any): any
              function writeFloatLE(val: any, offset: any, noAssert: any): any
              function writeInt16BE(value: any, offset: any, noAssert: any): any
              function writeInt16LE(value: any, offset: any, noAssert: any): any
              function writeInt32BE(value: any, offset: any, noAssert: any): any
              function writeInt32LE(value: any, offset: any, noAssert: any): any
              function writeInt8(value: any, offset: any, noAssert: any): any
              function writeIntBE(value: any, offset: any, byteLength: any, noAssert: any): any
              function writeIntLE(value: any, offset: any, byteLength: any, noAssert: any): any
              function writeUInt16BE(value: any, offset: any, noAssert: any): any
              function writeUInt16LE(value: any, offset: any, noAssert: any): any
              function writeUInt32BE(value: any, offset: any, noAssert: any): any
              function writeUInt32LE(value: any, offset: any, noAssert: any): any
              function writeUInt8(value: any, offset: any, noAssert: any): any
              function writeUIntBE(value: any, offset: any, byteLength: any, noAssert: any): any
              function writeUIntLE(value: any, offset: any, byteLength: any, noAssert: any): any
              namespace buffer {
                  // Too-deep object hierarchy from bcoin.crypto.schnorr.alg.buffer
                  const byteLength: any
                  // Too-deep object hierarchy from bcoin.crypto.schnorr.alg.buffer
                  const slice: any
              }
              namespace parent {
                  // Too-deep object hierarchy from bcoin.crypto.schnorr.alg.parent
                  const byteLength: any
                  // Too-deep object hierarchy from bcoin.crypto.schnorr.alg.parent
                  const slice: any
              }
          }
      }
      namespace siphash {
          class U64 {
              constructor(hi: any, lo: any)
              static fromRaw(data: any, off: any): any
              add(b: any): any
              rotl(b: any): any
              toRaw(): any
              xor(b: any): any
          }
          // Circular reference from bcoin.crypto.siphash
          const siphash256: any
          function siphash(data: any, key: any): any
      }
      namespace siphash256 {
          class U64 {
              constructor(hi: any, lo: any)
              static fromRaw(data: any, off: any): any
              add(b: any): any
              rotl(b: any): any
              toRaw(): any
              xor(b: any): any
          }
          // Circular reference from bcoin.crypto.siphash256
          const siphash256: any
          function siphash(data: any, key: any): any
      }
  }

  export namespace HD {
      class Mnemonic {
          static languages: string[]
          constructor(options: any)
          static fromEntropy(entropy: any, lang: any): any
          static fromJSON(json: any): any
          static fromOptions(options: any): any
          static fromPhrase(phrase: any): any
          static fromRaw(data: any): any
          static fromReader(br: any): any
          static getLanguage(word: any): any
          static getWordlist(language: any): any
          static isMnemonic(obj: any): any
          destroy(): void
          fromEntropy(entropy: any, lang: any): any
          fromJSON(json: any): any
          fromOptions(options: any): any
          fromPhrase(phrase: any): any
          fromRaw(data: any): any
          fromReader(br: any): any
          getEntropy(): any
          getPhrase(): any
          getSize(): any
          inspect(): any
          toJSON(): any
          toRaw(writer: any): any
          toSeed(passphrase: any): any
          toString(): any
          toWriter(bw: any): any
      }
      class PrivateKey {
          constructor(options: any)
          static fromBase58(xkey: any): any
          static fromExtended(data: any): any
          static fromExtendedReader(br: any): any
          static fromJSON(json: any): any
          static fromKey(key: any, entropy: any, network: any): any
          static fromMnemonic(mnemonic: any, network: any): any
          static fromOptions(options: any): any
          static fromRaw(raw: any): any
          static fromReader(br: any): any
          static fromSeed(seed: any, network: any): any
          static generate(network: any): any
          static isBase58(data: any): any
          static isHDPrivateKey(obj: any): any
          static isRaw(data: any): any
          static isValidPath(path: any): any
          compare(key: any): any
          derive(index: any, hardened: any, cache: any): any
          deriveAccount44(accountIndex: any, cache: any): any
          derivePath(path: any, cache: any): any
          derivePurpose45(cache: any): any
          destroy(pub: any): void
          equal(obj: any): any
          fromBase58(xkey: any): any
          fromExtended(data: any): any
          fromExtendedReader(br: any): any
          fromJSON(json: any): any
          fromKey(key: any, entropy: any, network: any): any
          fromMnemonic(mnemonic: any, network: any): any
          fromOptions(options: any): any
          fromRaw(raw: any): any
          fromReader(br: any): any
          fromSeed(seed: any, network: any): any
          getExtendedSize(): any
          getID(index: any): any
          getSize(): any
          isAccount44(accountIndex: any): any
          isMaster(): any
          isPurpose45(): any
          toBase58(network: any): any
          toExtended(network: any): any
          toExtendedWriter(bw: any, network: any): any
          toJSON(): any
          toPublic(): any
          toRaw(network: any): any
          toWriter(bw: any, network: any): any
          verifyNetwork(network: any): any
          xprivkey(): any
          xpubkey(): any
      }
      class PublicKey {
          constructor(options: any)
          static fromBase58(xkey: any): any
          static fromJSON(json: any): any
          static fromOptions(options: any): any
          static fromRaw(data: any): any
          static fromReader(br: any): any
          static isBase58(data: any): any
          static isHDPublicKey(obj: any): any
          static isRaw(data: any): any
          static isValidPath(path: any): any
          compare(key: any): any
          derive(index: any, hardened: any, cache: any): any
          deriveAccount44(accountIndex: any): any
          derivePath(path: any, cache: any): any
          derivePurpose45(): any
          destroy(): void
          equal(obj: any): any
          fromBase58(xkey: any): any
          fromJSON(json: any): any
          fromOptions(options: any): any
          fromRaw(raw: any): any
          fromReader(br: any): any
          getID(index: any): any
          getSize(): any
          isAccount44(accountIndex: any): any
          isMaster(): any
          isPurpose45(): any
          toBase58(network: any): any
          toJSON(): any
          toPublic(): any
          toRaw(network: any): any
          toWriter(bw: any, network: any): any
          verifyNetwork(network: any): any
          xprivkey(): any
          xpubkey(): any
      }
      function from(options: any, network: any): any
      function fromBase58(xkey: any): any
      function fromExtended(data: any): any
      function fromJSON(json: any): any
      function fromMnemonic(options: any, network: any): any
      function fromRaw(data: any): any
      function fromSeed(options: any, network: any): any
      function generate(network: any): any
      function isBase58(data: any): any
      function isHD(obj: any): any
      function isPrivate(obj: any): any
      function isPublic(obj: any): any
      function isRaw(data: any): any
  }

  export interface InputConstructor {
    new (options: any): Input
    fromCoin(coin: any): any
    fromJSON(json: any): any
    fromOptions(options: any): any
    fromOutpoint(outpoint: any): any
    fromRaw(data: any, enc: any): any
    fromReader(br: any): any
    fromTX(tx: any, index: any): any
    isInput(obj: any): any
  }
  export class Input {
    format(coin: any): any
    fromCoin(coin: any): any
    fromJSON(json: any): any
    fromOptions(options: any): any
    fromOutpoint(outpoint: any): any
    fromRaw(data: any): any
    fromReader(br: any): any
    fromTX(tx: any, index: any): any
    getAddress(coin: any): any
    getHash(enc: any): any
    getJSON(network: any, coin: any): any
    getRedeem(coin: any): any
    getSize(): any
    getSubtype(coin: any): any
    getType(coin: any): any
    inspect(): any
    isCoinbase(): any
    isFinal(): any
    isRBF(): any
    toJSON(network: any, coin: any): any
    toRaw(): any
    toWriter(bw: any): any
  }

  export interface KeyringConstructor {
    new (options: any, network?: any): Keyring
    fromJSON(json: any): any
    fromKey(key: any, compressed: any, network: any): any
    fromOptions(options: any): any
    fromPrivate(key: any, compressed: any, network: any): any
    fromPublic(key: any, network: any): any
    fromRaw(data: any): any
    fromReader(br: any): any
    fromScript(key: any, script: any, compressed: any, network: any): any
    fromSecret(data: any): any
    generate(compressed: any, network: any): any
    isKeyRing(obj: any): any
  }
  export interface Keyring {
    getAddress(enc?: any): any
    getHash(enc: any): any
    getKeyAddress(enc: any): any
    getKeyHash(enc: any): any
    getNestedAddress(enc: any): any
    getNestedHash(enc: any): any
    getPrivateKey(enc: any): any
    getProgram(): any
    getPublicKey(enc: any): any
    getRedeem(hash: any): any
    getScript(): any
    getScriptAddress(enc: any): any
    getScriptHash(enc: any): any
    getScriptHash160(enc: any): any
    getScriptHash256(enc: any): any
    getSecretSize(): any
    getSize(): any
    getType(): any
    getVersion(): any
    inspect(): any
    ownHash(hash: any): any
    ownOutput(tx: any, index: any): any
    refresh(): void
    sign(msg: any): any
    toJSON(): any
    toRaw(): any
    toSecret(): any
    toWriter(bw: any): any
    verify(msg: any, sig: any): any
    verifyNetwork(network: any): any
  }

  export interface MtxConstructor {
    new (options?: any): MTX
    MTX: any
    FundingError(msg: any, available: any, required: any): void
    fromJSON(json: any): any
    fromOptions(options: any): any
    fromRaw(data: any, enc: any): any
    fromReader(br: any): any
    fromTX(tx: any): any
    isMTX(obj: any): any
  }
  export interface MTX {
    addCoin(coin: any): any
    addInput(options: any): any
    addOutpoint(outpoint: any): any
    addOutput(options: any, value?: any): any
    addTX(tx: any, index: any, height: any): any
    avoidFeeSniping(height: any): void
    checkInputs(height: any, ret: any): any
    clone(): any
    estimateSize(...args: any[]): any
    format(): any
    fromOptions(options: any): any
    fund(...args: any[]): any
    getAddresses(): any
    getFee(): any
    getHashes(enc: any): any
    getInputAddresses(): any
    getInputHashes(enc: any): any
    getInputValue(): any
    getJSON(network: any): any
    getSigops(flags: any): any
    getSigopsCost(flags: any): any
    getSigopsSize(): any
    hasCoins(): any
    inspect(): any
    isInputSigned(index: any, coin: any): any
    isSigned(): any
    isVectorSigned(prev: any, vector: any): any
    scriptInput(index: any, coin: any, ring: any): any
    scriptVector(prev: any, vector: any, ring: any): any
    selectCoins(coins: any, options: any): any
    setLocktime(locktime: any): void
    setSequence(index: any, locktime: any, seconds: any): void
    sign(ring: any, type?: any): any
    signAsync(ring: any, type: any): any
    signInput(index: any, coin: any, ring: any, type: any): any
    signInputAsync(index: any, coin: any, ring: any, type: any): any
    signVector(prev: any, vector: any, sig: any, ring: any): any
    signature(index: any, prev: any, value: any, key: any, type: any, version: any): any
    sortMembers(): void
    subtractFee(fee: any, index: any): void
    template(ring: any): any
    toJSON(): any
    toTX(): any
    verify(flags: any): any
    verifyAsync(flags: any): any
  }

  export interface OutpointConstructor {
    new (hash: any, index: any): Outpoint
    fromJSON(json: any): any
    fromKey(key: any): any
    fromOptions(options: any): any
    fromRaw(data: any): any
    fromReader(br: any): any
    fromTX(tx: any, index: any): any
    toKey(hash: any, index: any): any
  }
  export interface Outpoint {
    fromJSON(json: any): any
    fromKey(key: any): any
    fromOptions(options: any): any
    fromRaw(data: any): any
    fromReader(br: any): any
    fromTX(tx: any, index: any): any
    getSize(): any
    inspect(): any
    isNull(): any
    rhash(): any
    toJSON(): any
    toKey(): any
    toRaw(): any
    toWriter(bw: any): any
  }

  export interface OutputConstructor {
    new (options: any): Output
    fromJSON(json: any): any
    fromOptions(options: any): any
    fromRaw(data: any, enc: any): any
    fromReader(br: any): any
    isOutput(obj: any): any
  }
  export interface Output {
    fromJSON(json: any): any
    fromOptions(options: any): any
    fromRaw(data: any): any
    fromReader(br: any): any
    getAddress(): any
    getDustThreshold(rate: any): any
    getHash(enc: any): any
    getJSON(network: any): any
    getSize(): any
    getType(): any
    inspect(): any
    isDust(rate: any): any
    toJSON(): any
    toRaw(): any
    toWriter(bw: any): any
  }

  export interface ScriptConstructor {
    new (options?: any): Script
    flags: {
      MANDATORY_VERIFY_FLAGS: number
      ONLY_STANDARD_VERIFY_FLAGS: number
      STANDARD_VERIFY_FLAGS: number
      VERIFY_CHECKLOCKTIMEVERIFY: number
      VERIFY_CHECKSEQUENCEVERIFY: number
      VERIFY_CLEANSTACK: number
      VERIFY_DERSIG: number
      VERIFY_DISCOURAGE_UPGRADABLE_NOPS: number
      VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: number
      VERIFY_LOW_S: number
      VERIFY_MAST: number
      VERIFY_MINIMALDATA: number
      VERIFY_MINIMALIF: number
      VERIFY_NONE: number
      VERIFY_NULLDUMMY: number
      VERIFY_NULLFAIL: number
      VERIFY_P2SH: number
      VERIFY_SIGPUSHONLY: number
      VERIFY_STRICTENC: number
      VERIFY_WITNESS: number
      VERIFY_WITNESS_PUBKEYTYPE: number
    }
    hashType: {
      ALL: number
      ANYONECANPAY: number
      NONE: number
      SINGLE: number
    }
    hashTypeByVal: {
      '1': string
      '128': string
      '2': string
      '3': string
    }
    opcodes: {
      OP_0: number
      OP_0NOTEQUAL: number
      OP_1: number
      OP_10: number
      OP_11: number
      OP_12: number
      OP_13: number
      OP_14: number
      OP_15: number
      OP_16: number
      OP_1ADD: number
      OP_1NEGATE: number
      OP_1SUB: number
      OP_2: number
      OP_2DIV: number
      OP_2DROP: number
      OP_2DUP: number
      OP_2MUL: number
      OP_2OVER: number
      OP_2ROT: number
      OP_2SWAP: number
      OP_3: number
      OP_3DUP: number
      OP_4: number
      OP_5: number
      OP_6: number
      OP_7: number
      OP_8: number
      OP_9: number
      OP_ABS: number
      OP_ADD: number
      OP_AND: number
      OP_BOOLAND: number
      OP_BOOLOR: number
      OP_CAT: number
      OP_CHECKLOCKTIMEVERIFY: number
      OP_CHECKMULTISIG: number
      OP_CHECKMULTISIGVERIFY: number
      OP_CHECKSEQUENCEVERIFY: number
      OP_CHECKSIG: number
      OP_CHECKSIGVERIFY: number
      OP_CODESEPARATOR: number
      OP_DEPTH: number
      OP_DIV: number
      OP_DROP: number
      OP_DUP: number
      OP_ELSE: number
      OP_ENDIF: number
      OP_EQUAL: number
      OP_EQUALVERIFY: number
      OP_EVAL: number
      OP_FALSE: number
      OP_FROMALTSTACK: number
      OP_GREATERTHAN: number
      OP_GREATERTHANOREQUAL: number
      OP_HASH160: number
      OP_HASH256: number
      OP_IF: number
      OP_IFDUP: number
      OP_INVALIDOPCODE: number
      OP_INVERT: number
      OP_LEFT: number
      OP_LESSTHAN: number
      OP_LESSTHANOREQUAL: number
      OP_LSHIFT: number
      OP_MAX: number
      OP_MIN: number
      OP_MOD: number
      OP_MUL: number
      OP_NEGATE: number
      OP_NIP: number
      OP_NOP: number
      OP_NOP1: number
      OP_NOP10: number
      OP_NOP2: number
      OP_NOP3: number
      OP_NOP4: number
      OP_NOP5: number
      OP_NOP6: number
      OP_NOP7: number
      OP_NOP8: number
      OP_NOP9: number
      OP_NOT: number
      OP_NOTIF: number
      OP_NUMEQUAL: number
      OP_NUMEQUALVERIFY: number
      OP_NUMNOTEQUAL: number
      OP_OR: number
      OP_OVER: number
      OP_PICK: number
      OP_PUBKEY: number
      OP_PUBKEYHASH: number
      OP_PUSHDATA1: number
      OP_PUSHDATA2: number
      OP_PUSHDATA4: number
      OP_RESERVED: number
      OP_RESERVED1: number
      OP_RESERVED2: number
      OP_RETURN: number
      OP_RIGHT: number
      OP_RIPEMD160: number
      OP_ROLL: number
      OP_ROT: number
      OP_RSHIFT: number
      OP_SHA1: number
      OP_SHA256: number
      OP_SIZE: number
      OP_SUB: number
      OP_SUBSTR: number
      OP_SWAP: number
      OP_TOALTSTACK: number
      OP_TRUE: number
      OP_TUCK: number
      OP_VER: number
      OP_VERIF: number
      OP_VERIFY: number
      OP_VERNOTIF: number
      OP_WITHIN: number
      OP_XOR: number
    }
    opcodesByVal: {
      '0': string
      '100': string
      '101': string
      '102': string
      '103': string
      '104': string
      '105': string
      '106': string
      '107': string
      '108': string
      '109': string
      '110': string
      '111': string
      '112': string
      '113': string
      '114': string
      '115': string
      '116': string
      '117': string
      '118': string
      '119': string
      '120': string
      '121': string
      '122': string
      '123': string
      '124': string
      '125': string
      '126': string
      '127': string
      '128': string
      '129': string
      '130': string
      '131': string
      '132': string
      '133': string
      '134': string
      '135': string
      '136': string
      '137': string
      '138': string
      '139': string
      '140': string
      '141': string
      '142': string
      '143': string
      '144': string
      '145': string
      '146': string
      '147': string
      '148': string
      '149': string
      '150': string
      '151': string
      '152': string
      '153': string
      '154': string
      '155': string
      '156': string
      '157': string
      '158': string
      '159': string
      '160': string
      '161': string
      '162': string
      '163': string
      '164': string
      '165': string
      '166': string
      '167': string
      '168': string
      '169': string
      '170': string
      '171': string
      '172': string
      '173': string
      '174': string
      '175': string
      '176': string
      '177': string
      '178': string
      '179': string
      '180': string
      '181': string
      '182': string
      '183': string
      '184': string
      '185': string
      '253': string
      '254': string
      '255': string
      '76': string
      '77': string
      '78': string
      '79': string
      '80': string
      '81': string
      '82': string
      '83': string
      '84': string
      '85': string
      '86': string
      '87': string
      '88': string
      '89': string
      '90': string
      '91': string
      '92': string
      '93': string
      '94': string
      '95': string
      '96': string
      '97': string
      '98': string
      '99': string
    }
    types: {
      MULTISIG: number
      NONSTANDARD: number
      NULLDATA: number
      PUBKEY: number
      PUBKEYHASH: number
      SCRIPTHASH: number
      WITNESSMALFORMED: number
      WITNESSMASTHASH: number
      WITNESSPUBKEYHASH: number
      WITNESSSCRIPTHASH: number
    }
    typesByVal: {
      '0': string
      '1': string
      '128': string
      '129': string
      '130': string
      '131': string
      '2': string
      '3': string
      '4': string
      '5': string
    }
    array(value: any): any
    bool(value: any): any
    checksig(msg: any, sig: any, key: any, flags: any): any
    fromAddress(address: any): any
    fromArray(code: any): any
    fromCode(code: any): any
    fromCommitment(hash: any, flags: any): any
    fromJSON(json: any): any
    fromMultisig(m: any, n: any, keys: any): any
    fromNulldata(flags: any): any
    fromOptions(options: any): any
    fromProgram(version: any, data: any): any
    fromPubkey(key: any): any
    fromPubkeyhash(hash: any): any
    fromRaw(data: any, enc: any): any
    fromReader(br: any): any
    fromScripthash(hash: any): any
    fromString(code: any): any
    getCoinbaseHeight(raw: any): any
    getSmall(op: any): any
    getWitnessSigops(input: any, output: any, witness: any, flags: any): any
    isCode(raw: any): any
    isCompressedEncoding(key: any): any
    isDummy(data: any): any
    isHash(hash: any): any
    isHashType(sig: any): any
    isKey(key: any): any
    isKeyEncoding(key: any): any
    isLowDER(sig: any): any
    isMinimal(data: any, opcode: any, flags: any): any
    isScript(obj: any): any
    isSignature(sig: any): any
    isSignatureEncoding(sig: any): any
    num(value: any, flags: any, size: any): any
    sign(msg: any, key: any, type: any): any
    validateKey(key: any, flags: any, version: any): any
    validateSignature(sig: any, flags: any): any
    verify(input: any, witness: any, output: any, tx: any, i: any, value: any, flags: any): any
    verifyMast(program: any, stack: any, output: any, flags: any, tx: any, i: any, value: any): any
    verifyProgram(witness: any, output: any, flags: any, tx: any, i: any, value: any): any
    witnessSigops(program: any, witness: any, flags: any): any
  }
  export interface Script {
    code: any
    raw: any
    clear (...args: any[]): any
    clone (...args: any[]): any
    compile (...args: any[]): any
    execute (...args: any[]): any
    forWitness (...args: any[]): any
    fromAddress (...args: any[]): any
    fromArray (...args: any[]): any
    fromCode (...args: any[]): any
    fromCommitment (...args: any[]): any
    fromJSON (...args: any[]): any
    fromMultisig (...args: any[]): any
    fromNulldata (...args: any[]): any
    fromOptions (...args: any[]): any
    fromProgram (...args: any[]): any
    fromPubkey (...args: any[]): any
    fromPubkeyhash (...args: any[]): any
    fromRaw (...args: any[]): any
    fromReader (...args: any[]): any
    fromScripthash (...args: any[]): any
    fromString (...args: any[]): any
    get (...args: any[]): any
    getAddress (...args: any[]): any
    getCodeSize (...args: any[]): any
    getCoinbaseHeight (...args: any[]): any
    getCommitmentHash (...args: any[]): any
    getInputAddress (...args: any[]): any
    getInputType (...args: any[]): any
    getNumber (...args: any[]): any
    getRedeem (...args: any[]): any
    getScripthashSigops (...args: any[]): any
    getSigops (...args: any[]): any
    getSize (...args: any[]): any
    getSmall (...args: any[]): any
    getString (...args: any[]): any
    getSubscript (...args: any[]): any
    getType (...args: any[]): any
    getVarSize (...args: any[]): any
    hash160 (...args: any[]): any
    indexOf (...args: any[]): any
    inject (...args: any[]): any
    insert (...args: any[]): any
    inspect (...args: any[]): any
    isCommitment (...args: any[]): any
    isMultisig (...args: any[]): any
    isMultisigInput (...args: any[]): any
    isNulldata (...args: any[]): any
    isProgram (...args: any[]): any
    isPubkey (...args: any[]): any
    isPubkeyInput (...args: any[]): any
    isPubkeyhash (...args: any[]): any
    isPubkeyhashInput (...args: any[]): any
    isPushOnly (...args: any[]): any
    isScripthash (...args: any[]): any
    isScripthashInput (...args: any[]): any
    isStandard (...args: any[]): any
    isUnknown (...args: any[]): any
    isUnknownInput (...args: any[]): any
    isUnspendable (...args: any[]): any
    isWitnessMasthash (...args: any[]): any
    isWitnessPubkeyhash (...args: any[]): any
    isWitnessScripthash (...args: any[]): any
    length (...args: any[]): any
    pop (...args: any[]): any
    push (...args: any[]): any
    remove (...args: any[]): any
    removeData (...args: any[]): any
    removeSeparators (...args: any[]): any
    set (...args: any[]): any
    sha256 (...args: any[]): any
    shift (...args: any[]): any
    test (...args: any[]): any
    toASM (...args: any[]): any
    toArray (...args: any[]): any
    toCode (...args: any[]): any
    toJSON (...args: any[]): any
    toProgram (...args: any[]): any
    toRaw (...args: any[]): any
    toWriter (...args: any[]): any
    unshift (...args: any[]): any
  }

  export interface TxConstructor {
    new (options: any): TX
    fromJSON(json: any): any
    fromOptions(options: any): any
    fromRaw(data: any, enc?: any): any
    fromReader(br: any): any
    isTX(obj: any): any
    isWitness(br: any): any
  }
  export interface TX {
    checkInputs(view: any, height: any, ret: any): any
    clone(): any
    format(view: any, entry: any, index: any): any
    frame(): any
    frameNormal(): any
    frameWitness(): any
    fromJSON(json: any): any
    fromOptions(options: any): any
    fromRaw(data: any): any
    fromReader(br: any): any
    fromWitnessReader(br: any): any
    getAddresses(view: any): any
    getBaseSize(): any
    getChainValue(view: any, height: any): any
    getFee(view: any): any
    getHashes(view: any, enc: any): any
    getInputAddresses(view: any): any
    getInputHashes(view: any, enc: any): any
    getInputValue(view: any): any
    getJSON(network: any, view: any, entry: any, index: any): any
    getLegacySigops(): any
    getMinFee(size: any, rate: any): any
    getModifiedSize(size: any): any
    getNormalSizes(): any
    getOutputAddresses(): any
    getOutputHashes(enc: any): any
    getOutputValue(): any
    getPrevout(): any
    getPriority(view: any, height: any, size: any): any
    getRate(view: any, size: any): any
    getRoundFee(size: any, rate: any): any
    getScripthashSigops(view: any): any
    getSigops(view: any, flags: any): any
    getSigopsCost(view: any, flags: any): any
    getSigopsSize(sigops: any): any
    getSize(): any
    getSizes(): any
    getVirtualSize(): any
    getWeight(): any
    getWitnessSizes(): any
    getWitnessStandard(view: any): any
    hasCoins(view: any): any
    hasStandardInputs(view: any): any
    hasStandardWitness(view: any, ret: any): any
    hasWitness(): any
    hash(enc: any): any
    hashSize(index: any, prev: any, type: any): any
    inspect(): any
    isCoinbase(): any
    isFinal(height: any, ts: any): any
    isFree(view: any, height: any, size: any): any
    isRBF(): any
    isSane(ret: any): any
    isStandard(ret: any): any
    isWatched(filter: any): any
    refresh(): void
    rhash(): any
    rwhash(): any
    signatureHash(index: any, prev: any, value: any, type: any, version: any): any
    signatureHashV0(index: any, prev: any, type: any): any
    signatureHashV1(index: any, prev: any, value: any, type: any): any
    toInv(): any
    toJSON(): any
    toNormal(): any
    toNormalWriter(bw: any): any
    toRaw(): any
    toWriter(bw: any): any
    txid(): any
    verify(view: any, flags: any): any
    verifyAsync(...args: any[]): any
    verifyInput(index: any, coin: any, flags: any): any
    verifyInputAsync(...args: any[]): any
    verifyLocktime(index: any, locktime: any): any
    verifySequence(index: any, locktime: any): any
    witnessHash(enc: any): any
    writeNormal(bw: any): any
    writeWitness(bw: any): any
    wtxid(): any
  }

  export namespace Utils {
    class AsyncObject {
        constructor()
        close(...args: any[]): any
        destroy(...args: any[]): any
        open(...args: any[]): any
    }
    class Bloom {
      MAX_BLOOM_FILTER_SIZE: number
      MAX_HASH_FUNCS: number
      flags: {
          ALL: number
          NONE: number
          PUBKEY_ONLY: number
      }
      flagsByVal: {
          '0': string
          '1': string
          '2': string
      }
      constructor(size: any, n: any, tweak: any, update: any)
      fromOptions(size: any, n: any, tweak: any, update: any): any
      fromRate(items: any, rate: any, update: any): any
      fromRaw(data: any, enc: any): any
      fromReader(br: any): any
      murmur3(data: any, seed: any): any
      add(val: any, enc: any): void
      added(val: any, enc: any): any
      fromOptions(size: any, n: any, tweak: any, update: any): any
      fromRaw(data: any): any
      fromReader(br: any): any
      getSize(): any
      hash(val: any, n: any): any
      isWithinConstraints(): any
      reset(): void
      test(val: any, enc: any): any
      toRaw(): any
      toWriter(bw: any): any
    }
    class BufferReader {
        constructor(data: any, zeroCopy: any)
        createChecksum(): any
        destroy(): void
        end(): any
        endData(zeroCopy: any): any
        getSize(): any
        left(): any
        read16(): any
        read16BE(): any
        read32(): any
        read32BE(): any
        read53(): any
        read53BE(): any
        read64(): any
        read64BE(): any
        read64BEBN(): any
        read64BN(): any
        read8(): any
        readBytes(size: any, zeroCopy: any): any
        readDouble(): any
        readDoubleBE(): any
        readFloat(): any
        readFloatBE(): any
        readHash(enc: any): any
        readNullString(enc: any): any
        readString(enc: any, size: any): any
        readU16(): any
        readU16BE(): any
        readU32(): any
        readU32BE(): any
        readU53(): any
        readU53BE(): any
        readU64(): any
        readU64BE(): any
        readU64BEBN(): any
        readU64BN(): any
        readU8(): any
        readVarBytes(zeroCopy: any): any
        readVarString(enc: any, limit: any): any
        readVarint(): any
        readVarint2(): any
        readVarint2BN(): any
        readVarintBN(): any
        seek(off: any): any
        skipVarint(): void
        skipVarint2(): void
        start(): any
        verifyChecksum(): any
      }
    class BufferWriter {
      constructor()
      destroy(): void
      fill(value: any, size: any): void
      getSize(): any
      render(keep: any): any
      seek(offset: any): void
      write16(value: any): void
      write16BE(value: any): void
      write32(value: any): void
      write32BE(value: any): void
      write64(value: any): void
      write64BE(value: any): void
      write64BEBN(value: any): void
      write64BN(value: any): void
      write8(value: any): void
      writeBytes(value: any): void
      writeChecksum(): void
      writeDouble(value: any): void
      writeDoubleBE(value: any): void
      writeFloat(value: any): void
      writeFloatBE(value: any): void
      writeHash(value: any): void
      writeNullString(value: any, enc: any): void
      writeString(value: any, enc: any): any
      writeU16(value: any): void
      writeU16BE(value: any): void
      writeU32(value: any): void
      writeU32BE(value: any): void
      writeU64(value: any): void
      writeU64BE(value: any): void
      writeU64BEBN(value: any): void
      writeU64BN(value: any): void
      writeU8(value: any): void
      writeVarBytes(value: any): void
      writeVarString(value: any, enc: any): any
      writeVarint(value: any): void
      writeVarint2(value: any): void
      writeVarint2BN(value: any): void
      writeVarintBN(value: any): void
    }
    class LRU {
      static LRU: any
      constructor(capacity: any, getSize: any)
      batch(): any
      clear(): void
      commit(): void
      drop(): void
      get(key: any): any
      has(key: any): any
      keys(): any
      push(key: any, value: any): void
      remove(key: any): any
      reset(): void
      set(key: any, value: any): void
      start(): void
      toArray(): any
      unpush(key: any): void
      values(): any
      }
    class List {
      constructor()
      static Item(value: any): void
      insert(ref: any, item: any): any
      pop(): any
      push(item: any): any
      remove(item: any): any
      replace(ref: any, item: any): void
      reset(): void
      shift(): any
      slice(total: any): any
      toArray(): any
      unshift(item: any): any
    }
    class Locker {
      constructor(named: any)
      static create(named: any): any
      destroy(): void
      drain(): void
      has(name: any): any
      hasPending(name: any): any
      isBusy(): any
      lock(arg1: any, arg2: any): any
      unlock(): void
      wait(): any
    }
    class MappedLocker {
      constructor()
      static create(): any
      destroy(): void
      has(name: any): any
      isBusy(): any
      lock(key: any, force: any): any
      unlock(key: any): any
    }
    class ProtoReader {
      constructor(data: any, zeroCopy: any)
      nextTag(): any
      readField(tag: any, opt: any): any
      readFieldBytes(tag: any, opt: any): any
      readFieldString(tag: any, opt: any, enc: any): any
      readFieldU32(tag: any, opt: any): any
      readFieldU64(tag: any, opt: any): any
      readFieldValue(tag: any, opt: any): any
      readVarint(): any
    }
    class ProtoWriter {
      constructor()
      writeFieldBytes(tag: any, data: any): void
      writeFieldString(tag: any, data: any, enc: any): void
      writeFieldU32(tag: any, value: any): void
      writeFieldU64(tag: any, value: any): void
      writeFieldVarint(tag: any, value: any): void
      writeVarint(num: any): void
    }
    class RollingFilter {
      constructor(items: any, rate: any)
      static fromRate(items: any, rate: any): any
      add(val: any, enc: any): void
      added(val: any, enc: any): any
      fromRate(items: any, rate: any): any
      hash(val: any, n: any): any
      reset(): void
      test(val: any, enc: any): any
    }
    class StaticWriter {
        constructor(size: any)
        destroy(): void
        fill(value: any, size: any): void
        getSize(): any
        render(keep: any): any
        seek(offset: any): void
        write16(value: any): void
        write16BE(value: any): void
        write32(value: any): void
        write32BE(value: any): void
        write64(value: any): void
        write64BE(value: any): void
        write64BEBN(value: any): void
        write64BN(value: any): void
        write8(value: any): void
        writeBytes(value: any): void
        writeChecksum(): void
        writeDouble(value: any): void
        writeDoubleBE(value: any): void
        writeFloat(value: any): void
        writeFloatBE(value: any): void
        writeHash(value: any): void
        writeNullString(value: any, enc: any): void
        writeString(value: any, enc: any): any
        writeU16(value: any): void
        writeU16BE(value: any): void
        writeU32(value: any): void
        writeU32BE(value: any): void
        writeU64(value: any): void
        writeU64BE(value: any): void
        writeU64BEBN(value: any): void
        writeU64BN(value: any): void
        writeU8(value: any): void
        writeVarBytes(value: any): void
        writeVarString(value: any, enc: any): any
        writeVarint(value: any): void
        writeVarint2(value: any): void
        writeVarint2BN(value: any): void
        writeVarintBN(value: any): void
      }
      function co(generator: any, ...args: any[]): any
      function lazy(require: any, exports: any): any
      function murmur3(data: any, seed: any): any
      function nextTick(callback: any, arg1: any, arg2: any, arg3: any, ...args: any[]): any
      function nfkd(str: any): any
      namespace ASN1 {
        function alignBitstr(data: any): any
        function explicit(br: any, type: any): any
        function formatOID(data: any): any
        function implicit(br: any, type: any): any
        function parseCert(data: any): any
        function parseRSAPrivate(data: any): any
        function parseRSAPublic(data: any): any
        function parseTBS(data: any): any
        function readAlgIdent(br: any): any
        function readBitstr(br: any): any
        function readCert(br: any): any
        function readExplicitInt(br: any, type: any, readNum: any): any
        function readInt(br: any, readNum: any): any
        function readName(br: any): any
        function readOID(br: any): any
        function readPubkey(br: any): any
        function readRSAPrivate(br: any): any
        function readRSAPublic(br: any): any
        function readSeq(br: any): any
        function readSize(br: any, primitive: any): any
        function readString(br: any): any
        function readTBS(br: any): any
        function readTag(br: any): any
        function readTime(br: any): any
        function readValidity(br: any): any
        function seq(br: any): any
      }
      namespace Bloom {
        class Rolling {
          constructor(items: any, rate: any)
          static fromRate(items: any, rate: any): any
          add(val: any, enc: any): void
          added(val: any, enc: any): any
          fromRate(items: any, rate: any): any
          hash(val: any, n: any): any
          reset(): void
          test(val: any, enc: any): any
        }
        namespace murmur3 {
          // Circular reference from bcoin.utils.Bloom.murmur3
          const murmur3: any
          function mul32(a: any, b: any): any
          function rotl32(w: any, b: any): any
          function sum32(a: any, b: any): any
        }
      }
      namespace IP {
        function hostname(host: any, port: any): any
        function isBroadcast(str: any): any
        function isLoopback(str: any): any
        function isMapped(buf: any): any
        function isNull(str: any): any
        function isPrivate(str: any): any
        function isPublic(str: any): any
        function isRoutable(str: any): any
        function isV4Format(str: any): any
        function isV6Format(str: any): any
        function isValid(str: any): any
        function loopback(family: any): any
        function normalize(str: any): any
        function parseHost(addr: any, fallback: any): any
        function parseV4(str: any, buf: any, offset: any): any
        function parseV6(str: any, buf: any, offset: any): any
        function toBuffer(str: any): any
        function toString(buf: any): any
        function version(str: any): any
      }
      namespace LRU {
        class Nil {
          constructor(size: any)
          batch(): any
          clear(): void
          commit(): void
          drop(): void
          get(key: any): void
          has(key: any): any
          keys(key: any): any
          push(key: any, value: any): void
          remove(key: any): void
          reset(): void
          set(key: any, value: any): void
          start(): void
          toArray(key: any): any
          unpush(key: any): void
          values(key: any): any
        }
      }
      namespace Locker {
        class Mapped {
          constructor()
          static create(): any
          destroy(): void
          has(name: any): any
          isBusy(): any
          lock(key: any, force: any): any
          unlock(key: any): any
        }
      }
      namespace PEM {
        function decode(pem: any): any
        function encode(der: any, type: any, suffix: any): any
        function parse(pem: any): any
      }
      namespace base58 {
        function decode(str: any): any
        function encode(data: any): any
      }
      namespace co {
        // Circular reference from bcoin.utils.co
        const co: any
        function cb(promise: any, callback: any): void
        function cob(generator: any, ...args: any[]): any
        function con(generator: any, ...args: any[]): any
        function every(...args: any[]): any
        function exec(gen: any): any
        function job(resolve: any, reject: any): any
        function promisify(func: any, ctx: any, ...args: any[]): any
        function spawn(generator: any, ctx: any): any
        function timeout(time: any): any
        function wait(): any
        function wrap(resolve: any, reject: any): any
      }
      namespace encoding {
        const HIGH_HASH: string
        const HIGH_HASH160: string
        const MAX_SAFE_ADDITION: number
        const MAX_SAFE_INTEGER: number
        const NULL_HASH: string
        const NULL_HASH160: string
        function U32(num: any): any
        function U32BE(num: any): any
        function U8(num: any): any
        function read53(data: any, off: any): any
        function read53BE(data: any, off: any): any
        function read64(data: any, off: any): any
        function read64BE(data: any, off: any): any
        function read64BEBN(data: any, off: any): any
        function read64BN(data: any, off: any): any
        function readU53(data: any, off: any): any
        function readU53BE(data: any, off: any): any
        function readU64(data: any, off: any): any
        function readU64BE(data: any, off: any): any
        function readU64BEBN(data: any, off: any): any
        function readU64BN(data: any, off: any): any
        function readVarint(data: any, off: any): any
        function readVarint2(data: any, off: any): any
        function readVarint2BN(data: any, off: any): any
        function readVarintBN(data: any, off: any): any
        function sizeVarBytes(data: any): any
        function sizeVarString(str: any, enc: any): any
        function sizeVarint(num: any): any
        function sizeVarint2(num: any): any
        function sizeVarint2BN(num: any): any
        function sizeVarintBN(num: any): any
        function sizeVarlen(len: any): any
        function skipVarint(data: any, off: any): any
        function skipVarint2(data: any, off: any): any
        function write64(dst: any, num: any, off: any): any
        function write64BE(dst: any, num: any, off: any): any
        function write64BEBN(dst: any, num: any, off: any): any
        function write64BN(dst: any, num: any, off: any): any
        function writeU64(dst: any, num: any, off: any): any
        function writeU64BE(dst: any, num: any, off: any): any
        function writeU64BEBN(dst: any, num: any, off: any): any
        function writeU64BN(dst: any, num: any, off: any): any
        function writeVarint(dst: any, num: any, off: any): any
        function writeVarint2(dst: any, num: any, off: any): any
        function writeVarint2BN(dst: any, num: any, off: any): any
        function writeVarintBN(dst: any, num: any, off: any): any
        // actually namespaces
        const DUMMY: any
        const MAX_HASH: any
        const MAX_HASH160: any
        const ONE_HASH: any
        const U32_MAX: any
        const U64_MAX: any
        const ZERO_HASH: any
        const ZERO_HASH160: any
        const ZERO_KEY: any
        const ZERO_SIG: any
        const ZERO_SIG64: any
        const ZERO_U32: any
        const ZERO_U64: any
      }
      namespace murmur3 {
        // Circular reference from bcoin.utils.murmur3
        const murmur3: any
        function mul32(a: any, b: any): any
        function rotl32(w: any, b: any): any
        function sum32(a: any, b: any): any
      }
      namespace protobuf {
        class ProtoReader {
          constructor(data: any, zeroCopy: any)
          nextTag(): any
          readField(tag: any, opt: any): any
          readFieldBytes(tag: any, opt: any): any
          readFieldString(tag: any, opt: any, enc: any): any
          readFieldU32(tag: any, opt: any): any
          readFieldU64(tag: any, opt: any): any
          readFieldValue(tag: any, opt: any): any
          readVarint(): any
        }
        class ProtoWriter {
          constructor()
          writeFieldBytes(tag: any, data: any): void
          writeFieldString(tag: any, data: any, enc: any): void
          writeFieldU32(tag: any, value: any): void
          writeFieldU64(tag: any, value: any): void
          writeFieldVarint(tag: any, value: any): void
          writeVarint(num: any): void
        }
        function readVarint(data: any, off: any): any
        function sizeVarint(num: any): any
        function slipVarint(num: any): any
        function writeVarint(data: any, num: any, off: any): any
      }
      namespace util {
      const HOME: string
      const MAX_SAFE_ADDITION: number
      const MAX_SAFE_INTEGER: number
      const isBrowser: boolean
      function binaryInsert(items: any, item: any, compare: any, uniq: any): any
      function binaryRemove(items: any, item: any, compare: any): any
      function binarySearch(items: any, key: any, compare: any, insert: any): any
      function cmp(a: any, b: any): any
      function concat(a: any, b: any): any
      function copy(data: any): any
      function date(ts: any): any
      function equal(a: any, b: any): any
      function error(...args: any[]): void
      function fastProp(obj: any): void
      function fmt(f: any, ...args: any[]): any
      function format(args: any, color: any): any
      function gc(): void
      function hex32(num: any): any
      function hex8(num: any): any
      function hrtime(time: any): any
      function indexOf(obj: any, data: any): any
      function inherits(obj: any, from: any): void
      function inspectify(obj: any, color: any): any
      function isBase58(obj: any): any
      function isDecimal(obj: any): any
      function isFloat(value: any): any
      function isHex(obj: any): any
      function isHex160(hash: any): any
      function isHex256(hash: any): any
      function isInt(value: any): any
      function isInt32(value: any): any
      function isInt53(value: any): any
      function isInt8(value: any): any
      function isNumber(value: any): any
      function isSafeInteger(value: any): any
      function isUInt32(value: any): any
      function isUInt53(value: any): any
      function isUInt8(value: any): any
      function isUpperCase(str: any): any
      function log(...args: any[]): void
      function mb(size: any): any
      function merge(p0: any, p1: any): any
      function mkdir(path: any, dirname: any): any
      function mkdirp(path: any): void
      function ms(): any
      function nextTick(callback: any, arg1: any, arg2: any, arg3: any, ...args: any[]): any
      function nonce(): any
      function nop(): void
      function normalize(path: any, dirname: any): any
      function now(): any
      function pad32(num: any): any
      function pad8(num: any): any
      function promisify(func: any, ...args: any[]): any
      function random(min: any, max: any): any
      function revHex(data: any): any
      function revMap(map: any): any
      function startsWith(str: any, prefix: any): any
      function strcmp(a: any, b: any): any
      function time(date: any): any
      function toMap(obj: any): any
      function uniq(obj: any): any
      function uniqBuffer(items: any): any
      function uptime(): any
      function values(map: any): any
    }
  }
}
