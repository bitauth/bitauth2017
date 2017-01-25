import { existsSync, writeFileSync, readFileSync } from 'fs'
import * as chalk from 'chalk'
import { Authhead } from 'bitauth'

import { config } from './config'

export function getAuthhead() {
  if (!existsSync(config.authtxPath)) {
    console.error(chalk.red(`No authhead found. Run 'yarn genid' to create one.\n`))
    process.exit(1)
  }
  return new Authhead(readFileSync(config.authtxPath).toString(), 'hex')
}

export function getSignature() {
  if (!existsSync(config.sigPath)) {
    console.error(chalk.red(`No signature found. Run 'yarn sign' to create one.\n`))
    process.exit(1)
  }
  return readFileSync(config.sigPath).toString()
}

export function getMessageBuffer() {
  if (!existsSync(config.sigPath)) {
    console.error(chalk.red(`No message found. Add a message at ${config.messagePath} to continue.\n`))
    process.exit(1)
  }
  return readFileSync(config.messagePath)
}
