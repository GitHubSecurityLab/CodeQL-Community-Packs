const crypto = require("crypto");

const algorithm = "aes-128-cbc";
const keysize = 16;
const hashrounds = 5000;
const hash = "blake2b512";
const salt = "vhufka9bgfidhmxobpoqmckc";

const password = process.argv[2];

const randomIV = crypto.randomBytes(32).toString('base64').slice(0, keysize);    // GOOD: IV is random - but not immediately from that random function

crypto.pbkdf2(password, salt, hashrounds, 100, keysize, hash, (err, key) => {
    const iv = crypto.createCipheriv(algorithm, key, randomIV);
});
