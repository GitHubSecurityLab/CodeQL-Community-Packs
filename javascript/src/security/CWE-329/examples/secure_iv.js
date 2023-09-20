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
