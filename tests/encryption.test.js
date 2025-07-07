const crypto = require('crypto');

// NOTE: Browser-based E2EE (Web Crypto API) and real-time chat (Socket.IO) are tested manually in the application UI. This file covers Node.js crypto and ECDH logic for demonstration and verification purposes.

// Mock the encryption utility for testing
class MockEncryption {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32;
    this.ivLength = 16;
    this.tagLength = 16;
  }

  generateKey() {
    return crypto.randomBytes(this.keyLength);
  }

  generateIV() {
    return crypto.randomBytes(this.ivLength);
  }

  encrypt(message, key) {
    try {
      const iv = this.generateIV();
      const cipher = crypto.createCipheriv(this.algorithm, key, iv);
      cipher.setAAD(Buffer.from('additional-data', 'utf8'));
      
      let encrypted = cipher.update(message, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
    } catch (error) {
      throw new Error('Encryption failed');
    }
  }

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
      throw new Error('Decryption failed');
    }
  }

  generateSharedKey(user1Key, user2Key) {
    const combined = Buffer.concat([user1Key, user2Key]);
    return crypto.createHash('sha256').update(combined).digest();
  }

  hashString(input) {
    return crypto.createHash('sha256').update(input).digest();
  }

  generateRandomString(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
}

const encryption = new MockEncryption();

describe('Encryption Tests', () => {
  test('should generate a valid encryption key', () => {
    const key = encryption.generateKey();
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  test('should generate a valid IV', () => {
    const iv = encryption.generateIV();
    expect(iv).toBeInstanceOf(Buffer);
    expect(iv.length).toBe(16);
  });

  test('should encrypt and decrypt a message successfully', () => {
    const key = encryption.generateKey();
    const originalMessage = 'Hello, this is a test message!';
    
    const encrypted = encryption.encrypt(originalMessage, key);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).toContain(':');
    
    const decrypted = encryption.decrypt(encrypted, key);
    expect(decrypted).toBe(originalMessage);
  });

  test('should fail to decrypt with wrong key', () => {
    const key1 = encryption.generateKey();
    const key2 = encryption.generateKey();
    const message = 'Test message';
    
    const encrypted = encryption.encrypt(message, key1);
    
    expect(() => {
      encryption.decrypt(encrypted, key2);
    }).toThrow('Decryption failed');
  });

  test('should fail to decrypt malformed data', () => {
    const key = encryption.generateKey();
    
    expect(() => {
      encryption.decrypt('invalid:data', key);
    }).toThrow('Invalid encrypted data format');
  });

  test('should generate different encrypted outputs for same message', () => {
    const key = encryption.generateKey();
    const message = 'Test message';
    
    const encrypted1 = encryption.encrypt(message, key);
    const encrypted2 = encryption.encrypt(message, key);
    
    expect(encrypted1).not.toBe(encrypted2);
  });

  test('should generate shared key correctly', () => {
    const key1 = encryption.generateKey();
    const key2 = encryption.generateKey();
    
    const sharedKey = encryption.generateSharedKey(key1, key2);
    expect(sharedKey).toBeInstanceOf(Buffer);
    expect(sharedKey.length).toBe(32);
  });

  test('should hash string correctly', () => {
    const input = 'test string';
    const hash = encryption.hashString(input);
    
    expect(hash).toBeInstanceOf(Buffer);
    expect(hash.length).toBe(32);
  });

  test('should generate random string', () => {
    const randomString = encryption.generateRandomString(16);
    expect(typeof randomString).toBe('string');
    expect(randomString.length).toBe(32); // hex encoding doubles the length
  });

  test('should handle empty message encryption', () => {
    const key = encryption.generateKey();
    const emptyMessage = '';
    
    const encrypted = encryption.encrypt(emptyMessage, key);
    const decrypted = encryption.decrypt(encrypted, key);
    
    expect(decrypted).toBe(emptyMessage);
  });

  test('should handle special characters in message', () => {
    const key = encryption.generateKey();
    const specialMessage = 'Hello! @#$%^&*()_+-=[]{}|;:,.<>?';
    
    const encrypted = encryption.encrypt(specialMessage, key);
    const decrypted = encryption.decrypt(encrypted, key);
    
    expect(decrypted).toBe(specialMessage);
  });

  test('should handle unicode characters', () => {
    const key = encryption.generateKey();
    const unicodeMessage = 'Hello 世界! 🌍';
    
    const encrypted = encryption.encrypt(unicodeMessage, key);
    const decrypted = encryption.decrypt(encrypted, key);
    
    expect(decrypted).toBe(unicodeMessage);
  });
});

describe('ECDH Key Exchange (Node.js)', () => {
  test('should establish a shared secret between two parties', () => {
    // Generate ECDH key pairs for Alice and Bob
    const alice = crypto.createECDH('prime256v1');
    alice.generateKeys();
    const bob = crypto.createECDH('prime256v1');
    bob.generateKeys();

    // Exchange and compute shared secrets
    const aliceSecret = alice.computeSecret(bob.getPublicKey());
    const bobSecret = bob.computeSecret(alice.getPublicKey());

    // Both secrets should be equal
    expect(aliceSecret.equals(bobSecret)).toBe(true);
    expect(aliceSecret.length).toBeGreaterThan(0);
  });
}); 