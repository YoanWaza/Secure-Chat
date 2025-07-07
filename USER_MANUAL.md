# Secure Chat Application - User Manual

## Table of Contents
1. [Getting Started](#getting-started)
2. [User Registration](#user-registration)
3. [User Login](#user-login)
4. [Chat Interface](#chat-interface)
5. [Security Features](#security-features)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

## Getting Started

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Internet connection
- JavaScript enabled in your browser

### Accessing the Application
1. Open your web browser
2. Navigate to the application URL (e.g., `http://localhost:3000`)
3. You will see the login/registration screen

- **Live Demo:** [https://secure-chat-b4pr.onrender.com](https://secure-chat-b4pr.onrender.com)
- The app uses HTTPS and is hosted on Render.
- If the app takes a minute to load, it is "waking up" from Render's free tier sleep mode.

## User Registration

### Step-by-Step Registration Process

1. **Access the Registration Form**
   - Click on the "Register" tab in the authentication interface
   - The registration form will appear

2. **Enter Your Information**
   - **Username**: Choose a unique username (3-20 characters)
   - **Password**: Create a strong password (minimum 6 characters)
   - **Confirm Password**: Re-enter your password exactly

3. **Password Requirements**
   - Minimum 6 characters
   - Can include letters, numbers, and special characters
   - Passwords are case-sensitive

4. **Complete Registration**
   - Click the "Register" button
   - If successful, you'll see a success message
   - You can then proceed to login

### Registration Tips
- Choose a username that's easy to remember but unique
- Use a strong password with a mix of characters
- Keep your credentials secure and don't share them

## User Login

### Step-by-Step Login Process

1. **Access the Login Form**
   - Click on the "Login" tab (default view)
   - Enter your registered username and password

2. **Enter Credentials**
   - **Username**: Your registered username
   - **Password**: Your account password

3. **Authentication**
   - Click the "Login" button
   - The system will verify your credentials
   - Upon successful login, you'll be redirected to the chat interface

### Login Security Features
- Passwords are securely hashed and never stored in plain text
- Failed login attempts are logged for security monitoring
- Sessions are managed with secure JWT tokens

## Chat Interface

### Main Components

#### 1. Header Section
- **Application Title**: "Secure Chat" with security icon
- **Current User**: Displays your username
- **Logout Button**: Click to securely log out

#### 2. Sidebar (Online Users)
- **User List**: Shows all currently online users
- **Online Status**: Green indicators show active users
- **User Interaction**: Click on users for private messaging

#### 3. Chat Area
- **Message Display**: Shows all private chat messages
- **Message Bubbles**: 
  - **Blue bubbles**: Your messages (right-aligned)
  - **White bubbles**: Other users' messages (left-aligned)
- **System Messages**: Gray notifications for user join/leave events

#### 4. Input Area
- **Recipient Selection**: Choose a user to send a private message
- **Message Input**: Type your message here (500 character limit)
- **Send Button**: Click to send your message
- **Character Counter**: Shows current message length
- **Encryption Status**: Indicates end-to-end encryption is active
- **Connection Status**: If the secure connection is not ready, you will see a message and the input will be disabled

### Sending Private Messages

1. **Select a Recipient**
   - Use the dropdown to select an online user to chat with privately
   - You cannot send messages to yourself

2. **Wait for Secure Connection**
   - The app will establish a secure connection (Diffie-Hellman key exchange) with the selected user
   - The message input will be enabled once the connection is ready
   - If the input is disabled, wait for the status message to clear

3. **Type and Send Your Message**
   - Type your message (maximum 500 characters)
   - Press Enter or click the send button
   - Your message will be encrypted and sent
   - It appears in the chat immediately

4. **Message Features**
   - All messages are private and end-to-end encrypted
   - Timestamps are displayed for each message
   - Messages are displayed in real-time

### Real-Time Features

#### User Notifications
- **User Joined**: Notification when someone joins the chat
- **User Left**: Notification when someone leaves the chat
- **Online Status**: Real-time updates of who's online

#### Message Encryption
- **Automatic Encryption**: All messages are encrypted before sending
- **Client-Side Decryption**: Messages are decrypted on your device
- **Security Indicator**: Lock icon shows encryption is active

## Security Features

### End-to-End Encryption

#### How It Works
1. **Message Encryption**: Your message is encrypted on your device before sending
2. **Secure Transmission**: Only encrypted data travels over the network
3. **Client Decryption**: Recipients decrypt messages on their devices
4. **Key Management**: Encryption keys are generated per session and never shared

#### Security Benefits
- **Confidentiality**: Only intended recipients can read messages
- **Integrity**: Any tampering with messages is detected
- **Authentication**: Ensures messages come from verified senders

### Authentication Security

#### Password Protection
- **Secure Hashing**: Passwords are hashed using bcrypt
- **Salt Rounds**: Additional security with 12 salt rounds
- **No Plain Text**: Passwords are never stored in readable format

#### Session Management
- **JWT Tokens**: Secure session tokens with 24-hour expiration
- **Automatic Logout**: Sessions expire for security
- **Token Validation**: All requests are validated

### Network Security

#### Security Headers
- **Content Security Policy**: Prevents XSS attacks
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-XSS-Protection**: Additional XSS protection

#### Rate Limiting
- **Request Limits**: Prevents abuse and brute force attacks
- **Time Windows**: Limits requests per 15-minute period
- **Automatic Blocking**: Excessive requests are automatically blocked

## Troubleshooting

### Common Issues and Solutions

#### 1. Cannot Connect to Chat
**Symptoms**: Loading spinner continues indefinitely
**Solutions**:
- Check your internet connection
- Refresh the page
- Clear browser cache and cookies
- Try a different browser

#### 2. Login Fails
**Symptoms**: "Invalid credentials" error
**Solutions**:
- Verify username and password are correct
- Check for typos (passwords are case-sensitive)
- Try registering a new account
- Clear browser cache

#### 3. Messages Not Sending
**Symptoms**: Messages don't appear in chat
**Solutions**:
- Check internet connection
- Refresh the page
- Try logging out and back in
- Check browser console for errors

#### 4. Encryption Errors
**Symptoms**: Messages show as "[Encrypted Message]"
**Solutions**:
- Clear browser cache and localStorage
- Log out and log back in
- Check if CryptoJS library is loaded
- Try a different browser

#### 5. Users Not Showing Online
**Symptoms**: Sidebar shows no online users
**Solutions**:
- Refresh the page
- Check if other users are actually online
- Verify your connection is stable
- Try logging out and back in

### Browser Compatibility

#### Supported Browsers
- **Chrome**: Version 80+
- **Firefox**: Version 75+
- **Safari**: Version 13+
- **Edge**: Version 80+

#### Required Features
- JavaScript enabled
- WebSocket support
- Local storage support
- Modern encryption APIs

### Performance Issues

#### Slow Loading
- Check internet connection speed
- Close unnecessary browser tabs
- Clear browser cache
- Try a different browser

#### High Memory Usage
- Close other applications
- Restart your browser
- Check for browser extensions that might interfere

### Slow to Load

- If the app takes up to a minute to load, it is starting up from Render's free tier sleep mode. This is normal and will be fast after the first load.

## Best Practices

### Security Best Practices

#### Password Security
- Use strong, unique passwords
- Don't reuse passwords from other accounts
- Change your password regularly
- Never share your credentials

#### Session Security
- Log out when using shared computers
- Don't stay logged in on public devices
- Clear browser data when using public computers
- Use private/incognito mode when appropriate

#### Message Security
- Be aware that messages are encrypted but not anonymous
- Don't share sensitive information in chat
- Be cautious with file sharing (if implemented)
- Report suspicious activity

### Communication Best Practices

#### Message Etiquette
- Be respectful to other users
- Use appropriate language
- Don't spam or send excessive messages
- Be patient with new users

#### Privacy Considerations
- Remember that online users can see your username
- Be mindful of what you share in group chats
- Consider using private messages for sensitive topics
- Respect others' privacy

### Technical Best Practices

#### Browser Usage
- Keep your browser updated
- Use security extensions when appropriate
- Enable automatic updates
- Regularly clear cache and cookies

#### Network Security
- Use secure networks when possible
- Avoid public Wi-Fi for sensitive conversations
- Use VPN if available
- Be aware of network monitoring

## Support and Help

### Getting Help
- Check this user manual first
- Look for error messages in the browser console
- Try the troubleshooting steps above
- Contact system administrators if issues persist

### Reporting Issues
When reporting issues, include:
- Browser type and version
- Operating system
- Error messages (if any)
- Steps to reproduce the problem
- Screenshots if helpful

### Feature Requests
- Suggest new features through appropriate channels
- Provide detailed descriptions of desired functionality
- Consider security implications of new features

---

**Note**: This application is designed for educational purposes and demonstrates cybersecurity concepts.