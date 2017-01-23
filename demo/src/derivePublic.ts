// if private data.json exists, exit with error, warn the user to delete old one before trying again
import { writeFileSync } from 'fs'
import * as chalk from 'chalk'

import { config } from './config'
import { getMasterKey, getFundingAddress, getIdentityBranch, getSigningBranch, getAddress } from './keys'

let master = getMasterKey()
let pub = {
  fundingAddress: getFundingAddress(master),
  identityAddress: getAddress(master, getIdentityBranch()),
  signingAddress: getAddress(master, getSigningBranch())
}

writeFileSync(config.publicPath, JSON.stringify(pub, null, 2))

console.log(chalk.inverse.bold(`Your testnet address is: ${pub.fundingAddress}`))
console.log()
console.log(chalk.yellow(`Once you've funded this address, run 'yarn genid' to create your BitAuth identity.`))
console.log()
