// if private data.json exists, exit with error, warn the user to delete old one before trying again
import * as chalk from 'chalk'
import * as request from 'request'
import { config } from './config'
import { getAuthhead } from './data'

let authheadRaw = getAuthhead()

console.log(`Broadcasting the latest authhead to the P2P network via ${config.insight} ...\n`)

request(`${config.insight}api/tx/send`, {method: 'POST', json: true, body: {rawtx: authheadRaw }},
        (err, res, json) => {
          if (err) {
            console.error(chalk.red(err))
            process.exit(1)
          }
          console.log(chalk.inverse(`Response:`))
          console.log(json)
          console.log()
        })
