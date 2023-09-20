
import crypto from 'crypto';

const data = "Hello World!";


const v1 = crypto.createHash('md5').update(data);
const v2 = crypto.createHash('sha1').update(data);

const v3 = crypto.createHash('sha256').update(data);
const v4 = crypto.createHash('sha512').update(data);

const hashsha1 = crypto.createHash('sha1');
hashsha1.update(data);
