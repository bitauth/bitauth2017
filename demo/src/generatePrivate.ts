// if private data.json exists, exit with error, warn the user to delete old one before trying again
import { existsSync, writeFileSync } from 'fs'
import * as assert from 'assert'

import { HD } from 'bitauth'
import * as chalk from 'chalk'

import { getMasterKey, getFundingAddress } from './keys'
import { config } from './config'

if (existsSync(config.privatePath)) {
  console.error(chalk.red(`A key has already been generated. To generate a new key, remove 'data/private.json'.\n`))
  process.exit(1)
}

let master = HD.fromMnemonic(null, 'testnet')
let priv = master.toJSON() // actually returns and object, not a JSON string

writeFileSync(config.privatePath, JSON.stringify(priv, null, 2))
assert(getMasterKey())

console.log(chalk.green(`A new key has been generated and written to: ${config.privatePath}`))
console.log()
