const config = {
  network: 'testnet',
  insight: 'https://test-insight.bitpay.com/',
  privatePath: 'data/private.json',
  publicPath: 'data/public.json',
  messagePath: 'data/message.txt',
  authtxPath: 'data/authhead.bitcointx',
  sigPath: 'data/signature.bitauthsig',
  addCoinsFromPreviousIndex: true, // ignored when authheadIndex < 1
  authheadIndex: 0,
  identitySatoshis:  13000000,
  signingSatoshis:   13000000,
  feeSatoshisPerByte:     130,
  algorithm: 'hash256'
}
export { config }
