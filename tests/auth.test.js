const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mock user storage for testing
const users = new Map();

// Mock authentication functions
class MockAuth {
  constructor() {
    this.JWT_SECRET = 'test-secret-key';
  }

  async hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
  }

  async verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
  }

  generateToken(username) {
    return jwt.sign({ username }, this.JWT_SECRET, { expiresIn: '24h' });
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, this.JWT_SECRET);
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  async registerUser(username, password) {
    if (users.has(username)) {
      throw new Error('Username already exists');
    }

    const hashedPassword = await this.hashPassword(password);
    users.set(username, {
      username,
      password: hashedPassword,
      createdAt: new Date()
    });

    return { username, createdAt: users.get(username).createdAt };
  }

  async loginUser(username, password) {
    const user = users.get(username);
    if (!user) {
      throw new Error('Invalid credentials');
    }

    const isValidPassword = await this.verifyPassword(password, user.password);
    if (!isValidPassword) {
      throw new Error('Invalid credentials');
    }

    const token = this.generateToken(username);
    return { token, username };
  }
}

const auth = new MockAuth();

describe('Authentication Tests', () => {
  beforeEach(() => {
    users.clear();
  });

  describe('Password Hashing', () => {
    test('should hash password correctly', async () => {
      const password = 'testPassword123';
      const hashedPassword = await auth.hashPassword(password);
      
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword).not.toBe(password);
      expect(hashedPassword.length).toBeGreaterThan(20);
    });

    test('should verify correct password', async () => {
      const password = 'testPassword123';
      const hashedPassword = await auth.hashPassword(password);
      
      const isValid = await auth.verifyPassword(password, hashedPassword);
      expect(isValid).toBe(true);
    });

    test('should reject incorrect password', async () => {
      const password = 'testPassword123';
      const wrongPassword = 'wrongPassword123';
      const hashedPassword = await auth.hashPassword(password);
      
      const isValid = await auth.verifyPassword(wrongPassword, hashedPassword);
      expect(isValid).toBe(false);
    });

    test('should generate different hashes for same password', async () => {
      const password = 'testPassword123';
      const hash1 = await auth.hashPassword(password);
      const hash2 = await auth.hashPassword(password);
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('JWT Token Management', () => {
    test('should generate valid JWT token', () => {
      const username = 'testuser';
      const token = auth.generateToken(username);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    test('should verify valid JWT token', () => {
      const username = 'testuser';
      const token = auth.generateToken(username);
      
      const decoded = auth.verifyToken(token);
      expect(decoded.username).toBe(username);
    });

    test('should reject invalid JWT token', () => {
      const invalidToken = 'invalid.token.here';
      
      expect(() => {
        auth.verifyToken(invalidToken);
      }).toThrow('Invalid token');
    });

    test('should reject expired token', () => {
      const username = 'testuser';
      const expiredToken = jwt.sign({ username }, auth.JWT_SECRET, { expiresIn: '0s' });
      
      // Wait a moment for token to expire
      setTimeout(() => {
        expect(() => {
          auth.verifyToken(expiredToken);
        }).toThrow('Invalid token');
      }, 100);
    });
  });

  describe('User Registration', () => {
    test('should register new user successfully', async () => {
      const username = 'newuser';
      const password = 'password123';
      
      const result = await auth.registerUser(username, password);
      
      expect(result.username).toBe(username);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(users.has(username)).toBe(true);
    });

    test('should reject duplicate username', async () => {
      const username = 'duplicateuser';
      const password = 'password123';
      
      await auth.registerUser(username, password);
      
      await expect(auth.registerUser(username, password))
        .rejects.toThrow('Username already exists');
    });

    test('should hash password during registration', async () => {
      const username = 'testuser';
      const password = 'password123';
      
      await auth.registerUser(username, password);
      const user = users.get(username);
      
      expect(user.password).not.toBe(password);
      expect(user.password.length).toBeGreaterThan(20);
    });
  });

  describe('User Login', () => {
    beforeEach(async () => {
      await auth.registerUser('testuser', 'password123');
    });

    test('should login with correct credentials', async () => {
      const result = await auth.loginUser('testuser', 'password123');
      
      expect(result.username).toBe('testuser');
      expect(result.token).toBeDefined();
      expect(typeof result.token).toBe('string');
    });

    test('should reject login with wrong username', async () => {
      await expect(auth.loginUser('wronguser', 'password123'))
        .rejects.toThrow('Invalid credentials');
    });

    test('should reject login with wrong password', async () => {
      await expect(auth.loginUser('testuser', 'wrongpassword'))
        .rejects.toThrow('Invalid credentials');
    });

    test('should generate valid token on successful login', async () => {
      const result = await auth.loginUser('testuser', 'password123');
      
      const decoded = auth.verifyToken(result.token);
      expect(decoded.username).toBe('testuser');
    });
  });

  describe('Security Tests', () => {
    test('should handle SQL injection attempts in username', async () => {
      const maliciousUsername = "'; DROP TABLE users; --";
      const password = 'password123';
      
      // Should not crash and should treat as normal username
      await auth.registerUser(maliciousUsername, password);
      expect(users.has(maliciousUsername)).toBe(true);
    });

    test('should handle very long passwords', async () => {
      const username = 'testuser';
      const longPassword = 'a'.repeat(1000);
      
      await auth.registerUser(username, longPassword);
      const result = await auth.loginUser(username, longPassword);
      
      expect(result.username).toBe(username);
    });

    test('should handle special characters in password', async () => {
      const username = 'testuser';
      const specialPassword = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      
      await auth.registerUser(username, specialPassword);
      const result = await auth.loginUser(username, specialPassword);
      
      expect(result.username).toBe(username);
    });

    test('should handle unicode characters in username', async () => {
      const unicodeUsername = '测试用户';
      const password = 'password123';
      
      await auth.registerUser(unicodeUsername, password);
      const result = await auth.loginUser(unicodeUsername, password);
      
      expect(result.username).toBe(unicodeUsername);
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty username', async () => {
      const username = '';
      const password = 'password123';
      
      await auth.registerUser(username, password);
      const result = await auth.loginUser(username, password);
      
      expect(result.username).toBe(username);
    });

    test('should handle empty password', async () => {
      const username = 'testuser';
      const password = '';
      
      await auth.registerUser(username, password);
      const result = await auth.loginUser(username, password);
      
      expect(result.username).toBe(username);
    });

    test('should handle very short passwords', async () => {
      const username = 'testuser';
      const shortPassword = '123';
      
      await auth.registerUser(username, shortPassword);
      const result = await auth.loginUser(username, shortPassword);
      
      expect(result.username).toBe(username);
    });
  });
}); 