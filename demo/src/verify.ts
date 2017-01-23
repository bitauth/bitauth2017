import { Message, SignatureTransaction } from 'bitauth'
import * as chalk from 'chalk'

import { config } from './config'
import { getAuthhead, getSignature, getMessageBuffer } from './data'
import { getMasterKey, getCurrentSigningKey } from './keys'

let authhead = getAuthhead()
let sigHex = getSignature()
const algorithm = config.algorithm

console.log(`Verifying the signature transaction, given authhead: ${authhead.getId()}\n`)

if (!SignatureTransaction.verifySignature(sigHex, authhead.getSigningOutput())) {
  console.error(chalk.red(`The Signature Transaction could not be validated with this authhead.`))
  console.log(chalk.red(`If this is unexpected, please report the issue: https://github.com/bitjson/bitauth/issues`))
  process.exit(1)
}

console.log(chalk.bgGreen.bold.white(`✔ Signature transaction is valid.`))
console.log()
console.log(`Verifying the message digest is correct:`)

let message = new Message(getMessageBuffer())
console.log(chalk.inverse(`Message as string:`))
console.log(message.toString())
console.log(chalk.inverse(`Message as hex:`))
console.log(message.toHex())

// get message digest
console.log(chalk.inverse(`Message digest using algorithm ${algorithm}:`))
let messageDigest = message.getDigest(algorithm)
let messageDigestHex = messageDigest.toString('hex')
console.log(messageDigestHex)
console.log()

console.log(chalk.inverse(`Signature transaction digest info:`))
let digestInfo = SignatureTransaction.getDigestOutputInfo(sigHex)
if (digestInfo) {
  console.log(`algorithm: ${digestInfo.algorithm}`)
  console.log(`message digest: ${digestInfo.messageDigest}`)

  if (digestInfo.algorithm !== algorithm || digestInfo.messageDigest !== messageDigestHex) {
    issue(`The signature transaction's digest info does not match ${config.messagePath}`)
  } else {
    console.log()
    console.log(chalk.bgGreen.bold.white(`✔ Message digest matches.`))
    console.log()
  }
} else {
  issue(`The signature transaction does not include a valid Digest Output.`)
}

function issue(issue: string) {
  console.error(chalk.red(issue))
  console.log(chalk.red(`If this is unexpected, please report the issue: https://github.com/bitjson/bitauth/issues`))
  console.log()
  process.exit(1)
}
