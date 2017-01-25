```
directory structure:
~/.bitauth/
  data/
    main
    testnet
  known_identities.json
  identities/
    AUTHBASE*.bitauthidentity
  logs/
    main.log
    testnet.log
```


```bash
$ bitauth FILENAME.bitauth #--verbose available?

DANGER: FILENAME claims to be signed by an unknown identity.

Identity (Authbase): examplef4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 # this is actually the first bitcoin TX, not BitPay

This identity claims the following:
Name: "Jason Dreyzehner"
Email: "jason@dreyzehner.com"
Comment: "To verify this identity, please visit https://identity.bitjson.com/"

Malicious actors often claim to be an entity you trust. If this identity is fake,
accepting it may harm your security. Have you verified that this is the
legitimate identity of Jason Dreyzehner?

[✖] No, I am not sure
[ ] Yes, I am sure the identity above belongs to Jason Dreyzehner

# NO

Before continuing, you will need to confirm that the identity above is Jason Dreyzehner.
You should consult multiple trusted sources when making your decision.

Some good sources include:

- a secure website (https://) run by Jason Dreyzehner
- multiple direct email corespondences with the identity
- a reputable directory of bitauth identities
- a trusted friend or contact who has also verified the identity

If you can confirm the identity, run this again to add it to your known identities.

# YES

What should this identity be called?
Identity nickname: Jason Dreyzehner|

Jason Dreyzehner has been added to your list of known identities.
# on complete

Validating FILENAME.bitauth:
[ora spinner, completes as checkmark]
[✔] Syncing the bitcoin blockchain – 15%
[✔] Fetching validation requirements of: Jason Dreyzehner
[✔] Verifying FILENAME.bitauth
# Valid
[✔] Success: FILENAME.bitauth was signed by Jason Dreyzehner.
[✔] Extracting FILENAME

FILENAME is now available at path/to/FILENAME.

# Invalid
[✖] Warning: FILENAME.bitauth has been modified, and may be unsafe.

It is recommended that you delete this file, as its contents may not be safe.
Would you like to delete it now?

[✖] Yes (recommended)
[ ] No, I will handle it myself

# Yes

FILENAME was trashed.

# No

FILENAME, which is located at path/to/FILENAME, has not been signed by Jason
Dreyzehner and should be handled with caution.

```

```
.bitauth file structure:
bson document
{
 generator: "BitAuth CLI", // generator (software which generated the file)
 gid: examplef4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 // generator identity
 format: "bitauthidentity"
 contents: {
  nickname: null,
  authbase_hash: examplef4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
  claims: [
    {
      message: 'f4184fc596403b9d638783cf57adf...' hex encoded bson message?
      // {
      //   name: "Jason Dreyzehner",
      //   kv: {
      //     email: "jason@dreyzehner.com",
      //     comment: "To verify this identity, please visit https://identity.bitjson.com/"
      //   }
      // }
      sigtx: 'f4184fc596403b9d638783cf57adf...' // hex encoded sigtx – this already includes the hashing algorithm used and the message digest
    }
  ],
  authchain: [ // optionally possible to include with file. Speeds up identity bootstrapping
    'f4184fc596403b9d638783cf57adf...', // the authbase is first
    'f4184fc596403b9d638783cf57adf...',
    'f4184fc596403b9d638783cf57adf...',
    {
      tx: 'f4184fc596403b9d638783cf57adf...',
      height: 440000
    } // the latest known authhead is last
  ]
 }
}
```
