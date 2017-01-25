// if private data.json exists, exit with error, warn the user to delete old one before trying again
import { existsSync, writeFileSync, readFileSync } from 'fs'
import * as assert from 'assert'

import { HD, Keyring } from 'bitauth'
import * as chalk from 'chalk'

import { config } from './config'

export function getMasterKey() {
  if (!existsSync(config.privatePath)) {
    console.error(chalk.red(`No private keys found. Run 'yarn genkey' to get started.\n`))
    process.exit(1)
  }

  let privWritten = JSON.parse(readFileSync(config.privatePath).toString())
  let master = HD.fromMnemonic(privWritten.mnemonic.phrase, config.network)
  return master
}

export function getFundingAddress(master: any) {
  return getAddress(master, getFundingBranch())
}

// for simplicity, we re-use the funding address
export function getFundingKey(master: any) {
  return getKey(master, getFundingBranch(), 0)
}

export function getCurrentSigningKey(master: any) {
  return getKey(master, getSigningBranch())
}

function getFundingBranch() {
  return 0
}

export function getIdentityBranch() {
  return 1
}

export function getSigningBranch() {
  return 2
}

export function getAddress (master: any, branchIndex: number) {
  let key = getKey(master, branchIndex)
  return new Keyring(key.privateKey, key.network).getAddress().toBase58()
}

export function getBranch (master: any, branchIndex: number) {
  let hardened = true
  return master.derive(`m/${branchIndex}`, hardened)
}

export function getKey (master: any, branchIndex: number, addressesIndex = config.authheadIndex) {
  return getBranch(master, branchIndex).derive(`m/${addressesIndex}`)
}
