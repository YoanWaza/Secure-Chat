const crypto = require('crypto');

class Encryption {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32; // 256 bits
    this.ivLength = 16; // 128 bits
    this.tagLength = 16; // 128 bits
  }

  // Generate a random encryption key
  generateKey() {
    return crypto.randomBytes(this.keyLength);
  }

  // Generate a random IV (Initialization Vector)
  generateIV() {
    return crypto.randomBytes(this.ivLength);
  }

  // Encrypt a message using AES-256-GCM
  encrypt(message, key) {
    try {
      const iv = this.generateIV();
      const cipher = crypto.createCipheriv(this.algorithm, key, iv);
      cipher.setAAD(Buffer.from('additional-data', 'utf8'));
      
      let encrypted = cipher.update(message, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      // Return IV + AuthTag + EncryptedData as hex string
      return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Encryption failed');
    }
  }

  // Decrypt a message using AES-256-GCM
  decrypt(encryptedData, key) {
    try {
      const parts = encryptedData.split(':');
      if (parts.length !== 3) {
        throw new Error('Invalid encrypted data format');
      }

      const iv = Buffer.from(parts[0], 'hex');
      const authTag = Buffer.from(parts[1], 'hex');
      const encrypted = parts[2];

      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
      decipher.setAuthTag(authTag);
      decipher.setAAD(Buffer.from('additional-data', 'utf8'));

      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      if (error.message === 'Invalid encrypted data format') {
        throw error;
      }
      console.error('Decryption error:', error);
      throw new Error('Decryption failed');
    }
  }

  // Generate a shared key for two users (simplified key exchange)
  generateSharedKey(user1Key, user2Key) {
    // In a real implementation, this would use proper key exchange protocols
    // like Diffie-Hellman or ECDH
    const combined = Buffer.concat([user1Key, user2Key]);
    return crypto.createHash('sha256').update(combined).digest();
  }

  // Hash a string for key derivation
  hashString(input) {
    return crypto.createHash('sha256').update(input).digest();
  }

  // Generate a secure random string
  generateRandomString(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Verify message integrity
  verifyMessageIntegrity(message, signature, publicKey) {
    try {
      const verifier = crypto.createVerify('SHA256');
      verifier.update(message);
      return verifier.verify(publicKey, signature, 'hex');
    } catch (error) {
      console.error('Signature verification error:', error);
      return false;
    }
  }

  // Sign a message
  signMessage(message, privateKey) {
    try {
      const signer = crypto.createSign('SHA256');
      signer.update(message);
      return signer.sign(privateKey, 'hex');
    } catch (error) {
      console.error('Message signing error:', error);
      throw new Error('Message signing failed');
    }
  }
}

module.exports = new Encryption(); 