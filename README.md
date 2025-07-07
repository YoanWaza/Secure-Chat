# Secure Chat Application

**Live Demo:** [https://secure-chat-b4pr.onrender.com](https://secure-chat-b4pr.onrender.com)

> This application is deployed on Render with full HTTPS support.  
> Note: The free Render service may take up to a minute to "wake up" if not accessed recently.

A real-time, end-to-end encrypted chat application built with Node.js, Socket.IO, and modern web technologies. This project demonstrates practical implementation of cybersecurity concepts including encryption, authentication, and secure communication protocols.

---

## Table of Contents
- [Features](#features)
- [Security Overview](#security-overview)
- [End-to-End Encryption Flow](#end-to-end-encryption-flow)
- [Authentication Flow](#authentication-flow)
- [Environment Variables](#environment-variables)
- [Installation & Local Usage](#installation--local-usage)
- [Deployment](#deployment)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Future Improvements](#future-improvements)
- [References](#references)
- [Disclaimer](#disclaimer)

---

## Features

- ✅ End-to-end encrypted private messaging (ECDH + AES-GCM)
- ✅ Secure user authentication (JWT)
- ✅ Password hashing (bcrypt)
- ✅ Rate limiting and security headers (Helmet)
- ✅ CORS configuration
- ✅ Real-time chat (Socket.IO)
- ✅ Modern, responsive UI
- ✅ Online user tracking

---

## Security Overview

- **End-to-End Encryption:** All messages are encrypted client-side using per-user session keys (AES-GCM), with keys established via Diffie-Hellman (ECDH) key exchange. The server never sees plaintext messages or private keys.
- **Authentication:** JWT-based authentication for all API and chat actions.
- **Password Hashing:** bcrypt with 12 salt rounds.
- **Rate Limiting:** Prevents brute-force and abuse attacks.
- **Helmet:** Secure HTTP headers.
- **CORS:** Configured for secure client-server communication.
- **Key Management:** No encryption keys are hardcoded or stored on the server.
- **HTTPS:** All traffic is encrypted in production (Render provides HTTPS).

---

## End-to-End Encryption Flow

1. **Key Exchange (Diffie-Hellman):**
   - After login, each client generates a Diffie-Hellman (ECDH, P-256) key pair in the browser.
   - Clients exchange public keys via the server (server only relays keys).
   - Each client derives a unique shared secret (session key) with every other user.

2. **Sending a Message:**
   - Sender selects a recipient.
   - Message is encrypted with the shared secret (AES-GCM, 256-bit).
   - Encrypted message is sent to the server, which relays it to the recipient.

3. **Receiving a Message:**
   - Recipient decrypts the message using the shared secret.
   - Only the intended recipient can read the message.

4. **Security Notes:**
   - No encryption keys are ever stored on the server or hardcoded.
   - Each user-to-user pair has a unique session key.
   - The server acts only as a relay for encrypted messages and public keys.

---

## Authentication Flow

- **Registration:**  
  - Client sends a POST request to `/api/register` with username and password.
  - Server hashes the password using bcrypt and stores the user.
- **Login:**  
  - Client sends a POST request to `/api/login` with username and password.
  - Server verifies credentials and returns a JWT.
- **Session Management:**  
  - Client stores JWT in localStorage and uses it for authentication.
  - JWT is sent as a Bearer token for protected API endpoints.
- **Chat Authentication:**  
  - Client sends JWT when connecting to Socket.IO.
  - Server verifies JWT before allowing chat access.

---

## Environment Variables

This application requires the following environment variable:

| Name         | Example Value           | Purpose                        |
|--------------|------------------------|--------------------------------|
| JWT_SECRET   | mySuperSecretKey123!@# | Secret key for JWT signing and verification |

- **On Render:** Set this in the Render dashboard under "Environment Variables".
- **For local development:**  
  ```sh
  export JWT_SECRET=mySuperSecretKey123!@#
  npm start
  ```
  Or create a `.env` file (if you use dotenv):
  ```
  JWT_SECRET=mySuperSecretKey123!@#
  ```

**Note:** Use a strong, unique value for `JWT_SECRET` in production.

---

## Installation & Local Usage

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secure-chat-app
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set environment variable**
   ```bash
   export JWT_SECRET=mySuperSecretKey123!@#
   ```

4. **(Optional) For local HTTPS:**  
   Generate self-signed certs:
   ```bash
   openssl req -nodes -new -x509 -keyout server.key -out server.cert
   ```
   Then run:
   ```bash
   npm start
   ```

5. **Access the application**
   - Local: [https://localhost:3000](https://localhost:3000)
   - Render: [https://secure-chat-b4pr.onrender.com](https://secure-chat-b4pr.onrender.com)

---

## Deployment

- This app is deployed at: [https://secure-chat-b4pr.onrender.com](https://secure-chat-b4pr.onrender.com)
- Render provides HTTPS automatically; no need to upload certificates.
- For other hosts, ensure HTTPS is enabled and `JWT_SECRET` is set.

---

## Testing

Run the test suite to verify security features:

```bash
npm test
```

- Includes tests for encryption, authentication, password hashing, JWT, and ECDH key exchange.
- Browser-based E2EE and chat are tested manually in the UI.

---

## Project Structure

```
secure-chat-app/
├── public/                 # Frontend assets
├── utils/                  # Encryption utilities
├── tests/                  # Test files
├── server.js               # Main server file
├── package.json            # Dependencies and scripts
└── README.md               # This file
```

---

## Troubleshooting

- **App slow to load:**  
  The Render free tier "sleeps" after 15 minutes of inactivity. The first visit may take up to a minute to "wake up."
- **Port already in use:**  
  Change port in `.env` or kill existing process.
- **Encryption errors:**  
  Clear browser cache/localStorage, check for JS errors, verify CryptoJS is loaded.

---

## Future Improvements

- 🔒 Message signing for non-repudiation
- 🔒 Message retention policies
- 🔒 Audit logging
- 🔒 Use a production database (PostgreSQL, MongoDB)
- 🔒 Two-factor authentication (2FA)
- 🔒 Advanced session management

---

## References

- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [JWT Specification](https://tools.ietf.org/html/rfc7519)
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
- [Socket.IO](https://socket.io/)
- [OWASP Security Guidelines](https://owasp.org/www-project-top-ten/)

---

## Disclaimer

This application is designed for educational purposes and demonstrates cybersecurity concepts. For production use, additional security measures should be implemented, including regular audits and compliance with relevant regulations.

--- 