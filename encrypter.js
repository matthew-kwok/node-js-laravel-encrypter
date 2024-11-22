const crypto = require('crypto');
const phpSerialize = require('php-serialize');

class Encrypter {
  constructor(key, cipher = 'aes-256-cbc') {
    const supportedCiphers = {
      'aes-128-cbc': { size: 16, aead: false },
      'aes-256-cbc': { size: 32, aead: false },
      'aes-128-gcm': { size: 16, aead: true },
      'aes-256-gcm': { size: 32, aead: true },
    };

    if (!Encrypter.supported(key, cipher)) {
      const ciphers = Object.keys(supportedCiphers).join(', ');
      throw new Error(`Unsupported cipher or incorrect key length. Supported ciphers are: ${ciphers}.`);
    }

    this.key = Buffer.from(key, 'utf8');
    this.cipher = cipher;
    this.supportedCiphers = supportedCiphers;
  }

  static supported(key, cipher) {
    const lowerCipher = cipher.toLowerCase();
    const supportedCiphers = {
      'aes-128-cbc': { size: 16, aead: false },
      'aes-256-cbc': { size: 32, aead: false },
      'aes-128-gcm': { size: 16, aead: true },
      'aes-256-gcm': { size: 32, aead: true },
    };
    const cipherConfig = supportedCiphers[lowerCipher];

    if (!cipherConfig) {
      return false;
    }

    return Buffer.from(key, 'utf8').length === cipherConfig.size;
  }

  encrypt(value, serialize = true) {
    const cipherConfig = this.supportedCiphers[this.cipher.toLowerCase()];
    const iv = crypto.randomBytes(openssl_cipher_iv_length(this.cipher));
    
    const serializedValue = serialize ? phpSerialize.serialize(value) : value;
    
    const cipher = crypto.createCipheriv(this.cipher, this.key, iv);
    
    let encrypted, tag;

    if (cipherConfig.aead) {
      encrypted = Buffer.concat([
        cipher.update(serializedValue, 'utf8'),
        cipher.final()
      ]);
      tag = cipher.getAuthTag();
    } else {
      encrypted = Buffer.concat([
        cipher.update(serializedValue, 'utf8'),
        cipher.final()
      ]);
      tag = undefined;
    }

    const encodedIv = iv.toString('base64');
    const encodedValue = encrypted.toString('base64');
    const encodedTag = tag ? tag.toString('base64') : '';

    // Generate MAC only for non-AEAD ciphers
    const mac = cipherConfig.aead 
      ? '' 
      : this.generateMac(encodedIv, encodedValue);

    const payload = {
      iv: encodedIv,
      value: encodedValue,
      mac: mac,
      tag: encodedTag
    };

    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }

  decrypt(payload, unserialize = true) {
    const jsonPayload = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    const cipherConfig = this.supportedCiphers[this.cipher.toLowerCase()];

    // Validate payload structure
    if (!this.validatePayload(jsonPayload)) {
      throw new Error('Invalid payload');
    }

    // Verify MAC for non-AEAD ciphers
    if (!cipherConfig.aead && !this.validateMac(jsonPayload)) {
      throw new Error('MAC validation failed');
    }

    const iv = Buffer.from(jsonPayload.iv, 'base64');
    const value = Buffer.from(jsonPayload.value, 'base64');
    const tag = jsonPayload.tag ? Buffer.from(jsonPayload.tag, 'base64') : undefined;

    const decipher = crypto.createDecipheriv(this.cipher, this.key, iv);

    if (cipherConfig.aead) {
      decipher.setAuthTag(tag);
    }

    const decrypted = Buffer.concat([
      decipher.update(value),
      decipher.final()
    ]);

    const decryptedValue = decrypted.toString('utf8');
    return unserialize ? phpSerialize.unserialize(decryptedValue) : decryptedValue;
  }

  generateMac(iv, value) {
    // Laravel's MAC generation method
    const macInput = iv + value;
    return crypto.createHmac('sha256', this.key)
      .update(macInput)
      .digest('hex');
  }

  validateMac(payload) {
    // Verify the MAC matches
    const computedMac = this.generateMac(payload.iv, payload.value);
    return crypto.timingSafeEqual(
      Buffer.from(computedMac),
      Buffer.from(payload.mac)
    );
  }

  validatePayload(payload) {
    // Ensure payload has required fields
    if (!payload || typeof payload !== 'object') {
      return false;
    }

    const requiredFields = ['iv', 'value', 'mac'];
    for (const field of requiredFields) {
      if (!payload[field] || typeof payload[field] !== 'string') {
        return false;
      }
    }

    return true;
  }

  encryptString(value) {
    return this.encrypt(value, false);
  }

  decryptString(payload) {
    return this.decrypt(payload, false);
  }
}

// Helper function to mimic PHP's openssl_cipher_iv_length
function openssl_cipher_iv_length(cipher) {
  const ivLengths = {
    'aes-128-cbc': 16,
    'aes-256-cbc': 16,
    'aes-128-gcm': 16,
    'aes-256-gcm': 16
  };
  return ivLengths[cipher] || 16;
}

module.exports = Encrypter;