# Node.js implementation of Laravel's Encrypter

Example
```js
const Encrypter = require('./encrypter.js');
const encrypter = new Encrypter("key_here");
const encryptedString = encrypter.encrypt('Hello');
const decryptedString = encrypter.decrypt(encryptedString);
```