# Using weak hashing algorithm

This query detects the use of a weak hashing algorithm in your code.

## Recommendation

Use stronger algorithm when hashing data.

```ts
import crypto from 'crypto';

// SHA256
const sha256 = crypto.createHash('sha256')
    .update(data);
// SHA512
const sha512 = crypto.createHash('sha512')
    .update(data);
```
