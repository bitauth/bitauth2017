import { writeFileSync } from 'fs'
import { SignatureTransaction, Keyring, Message } from 'bitauth'
import * as chalk from 'chalk'

import { config } from './config'
import { getMasterKey, getCurrentSigningKey } from './keys'
import { getAuthhead, getMessageBuffer } from './data'

let master = getMasterKey()

let authhead = getAuthhead()
const algorithm = config.algorithm

// get signing output from authhead
let signingKey = getCurrentSigningKey(master)
let keyring = new Keyring(signingKey.privateKey, signingKey.network)

// get message
console.log(`Signing the contents of ${config.messagePath} with authhead: ${authhead.getId()}\n`)
let message = new Message(getMessageBuffer())
console.log(chalk.inverse(`Message as string:`))
console.log(message.toString())
console.log(chalk.inverse(`Message as hex:`))
console.log(message.toHex())

// get message digest
console.log(chalk.inverse(`Message digest using algorithm ${algorithm}:`))
let messageDigest = message.getDigest(algorithm)
console.log(messageDigest.toString('hex'))

// create sigtx
let sigtx = new SignatureTransaction()
sigtx.addSigningOutput(authhead.getSigningOutput())
sigtx.setMessageDigest(algorithm, messageDigest)
sigtx.sign(keyring)

let sigJson = sigtx.toJSON()
let sigRaw = sigtx.toRaw()
let sigRawHex = sigRaw.toString('hex')

console.log(chalk.inverse(`A Signature Transaction was successfully created.`))
console.log()
console.log(`Digest Output Script Assembly:`)
console.log(sigtx.getDigestScriptAssembly())
console.log()

writeFileSync(config.sigPath, sigRawHex)

if (!sigtx.isValid()) {
  console.error(chalk.red(`The generated Authentication Transaction is invalid due to an unexpected error.`))
  console.log(chalk.red(`Please report this as a bug: https://github.com/bitjson/bitauth/issues`))
}
