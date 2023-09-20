# Insecure or static IV used in cryptographic function with Node crypto module
The code uses a cryptographic primitive that uses an Initialization Vector (IV), but does not generate IVs that are sufficiently unpredictable or unique. Some cryptographic primitives (such as block ciphers) require that IVs must have certain properties for the uniqueness and/or unpredictability of an IV. Primitives may vary in how important these properties are. If these properties are not maintained, e.g. by a bug in the code, then the cryptography may be weakened or broken by attacking the IVs themselves.


## Recommendation
With Node's crypto module, ensure that input to `createDecipheriv` or `createCipheriv` has been generated using a secure random source, such as `randomBytes` (from the same module).

Different kinds of cipher have different needs for their IVs. Generating a random IV is usually safest, but beware of CBC-MAC (that requires an IV of all-zeroes, by design).

NIST has recommendations for producing IVs, including for when you cannot make random ones. See the references for more information.


## Example
In this example, the IV is static.


```javascript
const crypto = require("crypto");

const algorithm = "aes-128-cbc";
const keysize = 16;
const hashrounds = 5000;
const hash = "blake2b512";
const salt = "vhufka9bgfidhmxobpoqmckc";

const password = process.argv[2];

const fixedIV = "0123456789abcdef";     // BAD: IV is static

crypto.pbkdf2(password, salt, hashrounds, 100, keysize, hash, (err, key) => {
    const iv = crypto.createCipheriv(algorithm, key, fixedIV);
});

```
The IV is generated securely in the example below.


```javascript
const crypto = require("crypto");

const algorithm = "aes-128-cbc";
const keysize = 16;
const hashrounds = 5000;
const hash = "blake2b512";
const salt = "vhufka9bgfidhmxobpoqmckc";

const password = process.argv[2];

const randomIV = crypto.randomBytes(keysize);    // GOOD: IV is random

crypto.pbkdf2(password, salt, hashrounds, 100, keysize, hash, (err, key) => {
    const iv = crypto.createCipheriv(algorithm, key, randomIV);
});

```

## References
* [crypto.createCipheriv](https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options)
* [NIST: Recommendation for Block Cipher Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
* Common Weakness Enumeration: [CWE-329](https://cwe.mitre.org/data/definitions/329.html).
* Common Weakness Enumeration: [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html).
