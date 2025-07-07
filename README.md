# Secure Chat Application

A real-time, end-to-end encrypted chat application built with Node.js, Socket.IO, and modern web technologies. This project demonstrates practical implementation of cybersecurity concepts including encryption, authentication, and secure communication protocols.

## 🛡️ Security Features

### End-to-End Encryption
- **AES-256-GCM** encryption for all messages
- Client-side encryption/decryption
- Secure key generation and management
- Message integrity verification

### Authentication & Authorization
- **JWT (JSON Web Tokens)** for session management
- **bcrypt** password hashing with salt rounds
- Secure user registration and login
- Token-based authentication for real-time connections

### Security Measures
- **Password Hashing:** All user passwords are hashed with bcrypt before storage. Plaintext passwords are never stored or transmitted.
- **JWT Authentication:** All API and chat actions require a valid JWT, issued only after successful login.
- **Rate Limiting:** The server applies rate limiting to API endpoints to prevent brute-force and abuse attacks.
- **Helmet:** The server uses Helmet to set secure HTTP headers and reduce common web vulnerabilities.
- **CORS:** Cross-Origin Resource Sharing is enabled and configured for secure client-server communication.
- **End-to-End Encryption:** All chat messages are encrypted client-side using per-user session keys (AES-GCM), with keys established via Diffie-Hellman (ECDH) key exchange. The server never sees plaintext messages or private keys.
- **Key Management:** No encryption keys are hardcoded or stored on the server. All key material is generated and managed in the browser.
- **HTTPS (Required for Production):** For true security, the app must be served over HTTPS in production to protect against network eavesdropping and man-in-the-middle attacks. (Local development may use HTTP, but this is not secure for real use.)

## 🚀 Features

- **Real-time messaging** using Socket.IO
- **User authentication** with secure password handling
- **Online user tracking**
- **Modern, responsive UI** with beautiful design
- **Message encryption** and decryption
- **Session persistence**
- **Cross-platform compatibility**

## 📋 Prerequisites

- Node.js (v14 or higher)
- npm or yarn package manager

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secure-chat-app
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment setup**
   Create a `.env` file in the root directory:
   ```env
   PORT=3000
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   NODE_ENV=development
   ```

4. **Start the application**
   ```bash
   # Development mode with auto-restart
   npm run dev
   
   # Production mode
   npm start
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:3000`

## 🧪 Testing

Run the test suite to verify security features:

```bash
npm test
```

The test suite includes:
- Encryption/decryption tests
- Authentication tests
- Password hashing verification
- JWT token validation
- Security edge cases

## 📁 Project Structure

```
secure-chat-app/
├── public/                 # Frontend assets
│   ├── index.html         # Main HTML file
│   ├── styles.css         # CSS styles
│   └── app.js            # Frontend JavaScript
├── utils/
│   └── encryption.js     # Encryption utilities
├── tests/                # Test files
│   ├── encryption.test.js
│   └── auth.test.js
├── server.js             # Main server file
├── package.json          # Dependencies and scripts
└── README.md            # This file
```

## 🔐 Security Implementation Details

### Encryption Algorithm
The application uses **AES-256-GCM** (Galois/Counter Mode) which provides:
- **Confidentiality**: Messages are encrypted and cannot be read without the key
- **Integrity**: Any tampering with encrypted data is detected
- **Authentication**: Ensures the message comes from the expected sender

### Key Management
- Each user session generates a unique encryption key
- Keys are never transmitted over the network
- Keys are stored only in client memory
- Keys are automatically cleared on logout

### Password Security
- **bcrypt** with 12 salt rounds for password hashing
- Passwords are never stored in plain text
- Secure password comparison using timing-safe methods

### JWT Implementation
- Tokens expire after 24 hours
- Secure token generation and verification
- Token-based authentication for real-time connections

## 🎨 User Interface

The application features a modern, responsive design with:
- **Clean authentication interface** with login/register tabs
- **Real-time chat interface** with message bubbles
- **Online users sidebar** showing active participants
- **Message encryption status** indicators
- **Responsive design** for mobile and desktop
- **Loading states** and error handling

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `JWT_SECRET` | JWT signing secret | Random string |
| `NODE_ENV` | Environment mode | development |

### Security Headers

The application includes comprehensive security headers via Helmet.js:
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Strict-Transport-Security (HSTS)

## 🚀 Deployment

### Production Deployment

1. **Set environment variables**
   ```env
   NODE_ENV=production
   JWT_SECRET=your-production-secret-key
   PORT=3000
   ```

2. **Install production dependencies**
   ```bash
   npm ci --only=production
   ```

3. **Start the application**
   ```bash
   npm start
   ```

### Docker Deployment

```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

## 🔍 Security Considerations

### Current Implementation
- ✅ End-to-end encryption
- ✅ Secure authentication
- ✅ Password hashing
- ✅ Rate limiting
- ✅ Security headers
- ✅ Input validation

### Production Recommendations
- 🔒 Use HTTPS with valid SSL certificates
- 🔒 Implement proper key exchange protocols (ECDH)
- 🔒 Add message signing for non-repudiation
- 🔒 Implement message retention policies
- 🔒 Add audit logging
- 🔒 Use a production database (PostgreSQL, MongoDB)
- 🔒 Implement proper session management
- 🔒 Add two-factor authentication (2FA)

## 🐛 Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Change port in .env file or kill existing process
   lsof -ti:3000 | xargs kill -9
   ```

2. **Socket connection issues**
   - Check firewall settings
   - Verify CORS configuration
   - Ensure client and server are on same domain

3. **Encryption errors**
   - Clear browser cache and localStorage
   - Check for JavaScript errors in console
   - Verify CryptoJS library is loaded

## 📚 API Documentation

### Authentication Endpoints

#### POST /api/register
Register a new user account.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "message": "User registered successfully"
}
```

#### POST /api/login
Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "token": "jwt-token-string",
  "username": "string"
}
```

### WebSocket Events

#### Client to Server
- `authenticate`: Authenticate with JWT token
- `sendMessage`: Send encrypted message to all users
- `sendPrivateMessage`: Send encrypted private message

#### Server to Client
- `userList`: List of online users
- `newMessage`: New encrypted message from user
- `privateMessage`: Private encrypted message
- `userJoined`: User joined notification
- `userLeft`: User left notification

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This application is designed for educational purposes and demonstrates cybersecurity concepts. For production use, additional security measures should be implemented, including:

- Proper key exchange protocols
- Certificate pinning
- Advanced threat detection
- Regular security audits
- Compliance with relevant regulations

## 🔗 References

- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [JWT Specification](https://tools.ietf.org/html/rfc7519)
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
- [Socket.IO](https://socket.io/)
- [OWASP Security Guidelines](https://owasp.org/www-project-top-ten/)

---

## End-to-End Encryption Flow (Updated)

This chat application uses true end-to-end encryption (E2EE) with secure key management. Here is how it works:

### 1. Key Exchange (Diffie-Hellman)
- After login, each client generates a Diffie-Hellman (ECDH, P-256) key pair in the browser.
- Each client sends their public key to every other online user via the server (the server only relays keys, never sees private keys).
- When a client receives another user's public key, it derives a unique shared secret (session key) with that user using its private key and the peer's public key.
- This shared secret is used for all encrypted communication between the two users.

### 2. Sending a Message
- The sender selects a recipient from the online users list.
- The sender encrypts the message using the shared secret (AES-GCM, 256-bit) established with the recipient.
- The encrypted message is sent to the server, which relays it to the intended recipient.
- The server cannot decrypt the message at any point.

### 3. Receiving a Message
- The recipient receives the encrypted message from the server.
- The recipient decrypts the message using the shared secret established with the sender.
- Only the intended recipient can decrypt and read the message.

### 4. Security Notes
- No encryption keys are ever stored on the server or hardcoded in the codebase.
- Each user-to-user pair has a unique session key, ensuring confidentiality and forward secrecy.
- The server acts only as a relay for encrypted messages and public keys.

## Authentication Flow

- **Registration:**
  - The client sends a POST request to `/api/register` with a username and password.
  - The server hashes the password using bcrypt and stores the user securely.
  - If the username is already taken, registration fails.

- **Login:**
  - The client sends a POST request to `/api/login` with username and password.
  - The server verifies the credentials by comparing the password hash.
  - If successful, the server returns a JWT (JSON Web Token) to the client.

- **Session Management:**
  - The client stores the JWT in localStorage and uses it for authentication in future requests.
  - The JWT is sent as a Bearer token in the Authorization header for protected API endpoints.

- **Chat Authentication:**
  - When connecting to the chat server (Socket.IO), the client sends the JWT for authentication.
  - The server verifies the JWT before allowing the user to join the chat and appear online.
  - Only authenticated users can send/receive messages and participate in the chat. 