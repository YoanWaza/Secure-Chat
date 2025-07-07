// Global variables
let socket;
let currentUser = null;
let encryptionKey = null;
let onlineUsers = [];
let dhKeyPair = null;
let peerPublicKeys = {};
let sharedSecrets = {};

// DOM elements
const authContainer = document.getElementById('auth-container');
const chatContainer = document.getElementById('chat-container');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const chatMessages = document.getElementById('chat-messages');
const usersList = document.getElementById('users-list');
const currentUserSpan = document.getElementById('current-user');
const logoutBtn = document.getElementById('logout-btn');
const loading = document.getElementById('loading');
const messageCounter = document.getElementById('message-counter');
const recipientSelect = document.getElementById('recipient-select');
const statusMessage = document.createElement('div');
statusMessage.id = 'input-status-message';
statusMessage.style.color = '#c53030';
statusMessage.style.marginTop = '5px';
const chatInputArea = document.querySelector('.chat-input-area');
chatInputArea.appendChild(statusMessage);

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    checkStoredAuth();
    // Add tab switching event listeners
    document.getElementById('login-tab').addEventListener('click', () => showTab('login'));
    document.getElementById('register-tab').addEventListener('click', () => showTab('register'));
});

// Initialize event listeners
function initializeEventListeners() {
    // Form submissions
    loginForm.addEventListener('submit', handleLogin);
    registerForm.addEventListener('submit', handleRegister);
    
    // Chat functionality
    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
    
    // Message counter
    messageInput.addEventListener('input', updateMessageCounter);
    
    // Logout
    logoutBtn.addEventListener('click', logout);
}

// Check for stored authentication
function checkStoredAuth() {
    const token = localStorage.getItem('chatToken');
    const username = localStorage.getItem('chatUsername');
    
    if (token && username) {
        currentUser = username;
        initializeSocket(token);
    }
}

// Show/hide tabs
function showTab(tabName) {
    const tabs = document.querySelectorAll('.tab-btn');
    const forms = document.querySelectorAll('.auth-form');
    
    tabs.forEach(tab => tab.classList.remove('active'));
    forms.forEach(form => form.style.display = 'none');
    
    if (tabName === 'login') {
        document.querySelector('.tab-btn:first-child').classList.add('active');
        loginForm.style.display = 'flex';
    } else {
        document.querySelector('.tab-btn:last-child').classList.add('active');
        registerForm.style.display = 'flex';
    }
}

// Handle user registration
async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;
    
    if (password !== confirmPassword) {
        showMessage('Passwords do not match', 'error');
        return;
    }
    
    if (password.length < 6) {
        showMessage('Password must be at least 6 characters long', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showMessage('Registration successful! Please login.', 'success');
            showTab('login');
            registerForm.reset();
        } else {
            showMessage(data.error, 'error');
        }
    } catch (error) {
        showMessage('Registration failed. Please try again.', 'error');
    }
}

// Handle user login
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.username;
            localStorage.setItem('chatToken', data.token);
            localStorage.setItem('chatUsername', data.username);
            
            initializeSocket(data.token);
        } else {
            showMessage(data.error, 'error');
        }
    } catch (error) {
        showMessage('Login failed. Please try again.', 'error');
    }
}

// Initialize Socket.IO connection
function initializeSocket(token) {
    showLoading(true);
    
    socket = io();
    
    socket.on('connect', () => {
        console.log('Connected to server');
        socket.emit('authenticate', { token });
    });
    
    socket.on('authenticated', () => {
        showLoading(false);
        showChatInterface();
    });
    
    socket.on('authError', (data) => {
        showLoading(false);
        showMessage(data.error, 'error');
        logout();
    });
    
    socket.on('userList', (users) => {
        onlineUsers = users;
        updateUsersList();
        setTimeout(() => {
            initiateDHExchange();
        }, 500);
    });
    
    socket.on('userJoined', (data) => {
        addSystemMessage(`${data.username} joined the chat`);
    });
    
    socket.on('userLeft', (data) => {
        addSystemMessage(`${data.username} left the chat`);
    });
    
    socket.on('newMessage', (data) => {
        if (data.from !== currentUser) {
            displayMessage(data.from, data.message, data.timestamp, false);
        }
    });
    
    socket.on('privateMessage', (data) => {
        if (data.from !== currentUser) {
            displayMessage(data.from, data.message, data.timestamp, false, true);
        }
    });
    
    socket.on('error', (data) => {
        showMessage(data.error, 'error');
    });
    
    socket.on('disconnect', () => {
        addSystemMessage('Connection lost. Trying to reconnect...');
    });

    // Register DH public key handler here
    socket.on('receiveDHPublicKey', async (data) => {
        console.log('[DEBUG] Received DH public key from', data.from);
        // Import peer's public key
        const peerPublicKey = await window.crypto.subtle.importKey(
            'jwk',
            data.publicKey,
            {
                name: 'ECDH',
                namedCurve: 'P-256',
            },
            true,
            []
        );
        peerPublicKeys[data.from] = peerPublicKey;
        // Derive shared secret
        const sharedSecret = await window.crypto.subtle.deriveKey(
            {
                name: 'ECDH',
                public: peerPublicKey,
            },
            dhKeyPair.privateKey,
            {
                name: 'AES-GCM',
                length: 256,
            },
            false,
            ['encrypt', 'decrypt']
        );
        sharedSecrets[data.from] = sharedSecret;
        console.log('[DEBUG] Shared secret established with', data.from);
        onSharedSecretEstablished(data.from);
    });
}

// After authentication, generate DH key pair and exchange public keys
async function initiateDHExchange() {
    // Generate DH key pair using SubtleCrypto
    dhKeyPair = await window.crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256',
        },
        true,
        ['deriveKey', 'deriveBits']
    );
    // Export public key
    const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', dhKeyPair.publicKey);
    onlineUsers.forEach(user => {
        if (user !== currentUser) {
            console.log('[DEBUG] Sending DH public key to', user);
            socket.emit('sendDHPublicKey', {
                to: user,
                publicKey: publicKeyJwk
            });
        }
    });
}

// Update encryptMessage and decryptMessage to use per-peer shared secret
async function encryptMessage(message, toUser) {
    const secret = sharedSecrets[toUser];
    if (!secret) throw new Error('No shared secret with user: ' + toUser);
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        secret,
        enc.encode(message)
    );
    // Return base64 encoded iv + ciphertext
    return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(ciphertext)));
}

async function decryptMessage(encryptedMessage, fromUser) {
    const secret = sharedSecrets[fromUser];
    if (!secret) throw new Error('No shared secret with user: ' + fromUser);
    const data = atob(encryptedMessage);
    const iv = new Uint8Array([...data].slice(0, 12).map(c => c.charCodeAt(0)));
    const ciphertext = new Uint8Array([...data].slice(12).map(c => c.charCodeAt(0)));
    const dec = new TextDecoder();
    const plaintext = await window.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        secret,
        ciphertext
    );
    return dec.decode(plaintext);
}

// Update users list and recipient dropdown
function updateUsersList() {
    usersList.innerHTML = '';
    recipientSelect.innerHTML = '';
    let firstRecipient = null;
    onlineUsers.forEach(user => {
        if (user !== currentUser) {
            const userDiv = document.createElement('div');
            userDiv.className = 'user-item online';
            userDiv.textContent = user;
            userDiv.onclick = () => startPrivateChat(user);
            usersList.appendChild(userDiv);
            // Add to recipient dropdown
            const option = document.createElement('option');
            option.value = user;
            option.textContent = user;
            recipientSelect.appendChild(option);
            if (!firstRecipient) firstRecipient = user;
        }
    });
    // Auto-select the first available recipient
    if (firstRecipient) {
        recipientSelect.value = firstRecipient;
        checkSendAvailability();
    } else {
        sendBtn.disabled = true;
        messageInput.disabled = true;
    }
}

// Check if send button and input should be enabled, and show status
function checkSendAvailability() {
    const recipient = recipientSelect.value;
    if (!recipient) {
        sendBtn.disabled = true;
        messageInput.disabled = true;
        statusMessage.textContent = 'No recipient selected.';
        console.log('[DEBUG] Input disabled: No recipient selected.');
    } else if (!sharedSecrets[recipient]) {
        sendBtn.disabled = true;
        messageInput.disabled = true;
        statusMessage.textContent = 'Waiting for secure connection with ' + recipient + '...';
        console.log('[DEBUG] Input disabled: Waiting for shared secret with', recipient);
    } else {
        sendBtn.disabled = false;
        messageInput.disabled = false;
        statusMessage.textContent = '';
        console.log('[DEBUG] Input enabled for recipient', recipient);
    }
}

// Listen for recipient selection changes
recipientSelect.addEventListener('change', checkSendAvailability);

// When a DH key is established, re-check send availability
async function onSharedSecretEstablished(user) {
    checkSendAvailability();
}

// In sendMessage, show a message if the shared secret is not ready
async function sendMessage() {
    const message = messageInput.value.trim();
    if (!message || !socket) return;
    const recipient = recipientSelect.value;
    if (!recipient) {
        showMessage('Please select a recipient.', 'error');
        return;
    }
    if (!sharedSecrets[recipient]) {
        showMessage('Secure connection with ' + recipient + ' is not ready yet. Please wait.', 'error');
        return;
    }
    try {
        const encryptedMessage = await encryptMessage(message, recipient);
        socket.emit('sendPrivateMessage', {
            encryptedMessage: encryptedMessage,
            to: recipient,
            isPrivate: true
        });
        // Display own message as private
        displayMessage(currentUser, '[Private to ' + recipient + '] ' + message, new Date().toISOString(), true, true);
        messageInput.value = '';
        updateMessageCounter();
    } catch (error) {
        showMessage('Failed to send message', 'error');
    }
}

// Always show private context in displayMessage
async function displayMessage(from, encryptedMessage, timestamp, isOwn = false, isPrivate = true) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message-item';
    const messageContent = document.createElement('div');
    messageContent.className = `message-content ${isOwn ? 'sent' : 'received'}`;
    const messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';
    const senderName = document.createElement('span');
    senderName.textContent = isOwn ? 'You (Private)' : from + ' (Private)';
    const messageTime = document.createElement('span');
    messageTime.textContent = formatTime(timestamp);
    messageHeader.appendChild(senderName);
    messageHeader.appendChild(messageTime);
    const messageText = document.createElement('div');
    messageText.className = 'message-text';
    if (encryptedMessage.startsWith('[Private to')) {
        messageText.textContent = encryptedMessage;
    } else {
    try {
            const decryptedMessage = await decryptMessage(encryptedMessage, from);
        messageText.textContent = decryptedMessage;
    } catch (error) {
        messageText.textContent = '[Message could not be decrypted]';
        messageText.style.color = '#e53e3e';
    }
    }
    messageContent.appendChild(messageHeader);
    messageContent.appendChild(messageText);
    messageDiv.appendChild(messageContent);
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
}

// Add system message
function addSystemMessage(message) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message-item';
    messageDiv.style.textAlign = 'center';
    messageDiv.style.margin = '10px 0';
    
    const systemMessage = document.createElement('div');
    systemMessage.style.display = 'inline-block';
    systemMessage.style.padding = '8px 16px';
    systemMessage.style.background = '#e2e8f0';
    systemMessage.style.color = '#4a5568';
    systemMessage.style.borderRadius = '15px';
    systemMessage.style.fontSize = '0.9rem';
    systemMessage.style.fontStyle = 'italic';
    systemMessage.textContent = message;
    
    messageDiv.appendChild(systemMessage);
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
}

// Start private chat (placeholder for future implementation)
function startPrivateChat(username) {
    // This would open a private chat window
    console.log(`Starting private chat with ${username}`);
}

// Update message counter
function updateMessageCounter() {
    const length = messageInput.value.length;
    messageCounter.textContent = `${length}/500`;
    
    if (length > 450) {
        messageCounter.style.color = '#e53e3e';
    } else if (length > 400) {
        messageCounter.style.color = '#d69e2e';
    } else {
        messageCounter.style.color = '#718096';
    }
}

// Format timestamp
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Scroll to bottom of chat
function scrollToBottom() {
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Show chat interface
function showChatInterface() {
    authContainer.style.display = 'none';
    chatContainer.style.display = 'flex';
    currentUserSpan.textContent = `Logged in as: ${currentUser}`;
    addSystemMessage('Welcome to Secure Chat! Your messages are end-to-end encrypted.');
}

// Show loading spinner
function showLoading(show) {
    loading.style.display = show ? 'flex' : 'none';
}

// Show message
function showMessage(message, type = 'info') {
    const messageDiv = document.getElementById('auth-message');
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    
    setTimeout(() => {
        messageDiv.textContent = '';
        messageDiv.className = 'message';
    }, 5000);
}

// Logout
function logout() {
    if (socket) {
        socket.disconnect();
    }
    
    localStorage.removeItem('chatToken');
    localStorage.removeItem('chatUsername');
    
    currentUser = null;
    encryptionKey = null;
    onlineUsers = [];
    
    chatContainer.style.display = 'none';
    authContainer.style.display = 'block';
    
    // Clear forms
    loginForm.reset();
    registerForm.reset();
    
    // Clear messages
    chatMessages.innerHTML = '';
    usersList.innerHTML = '';
    
    showMessage('Logged out successfully', 'success');
} 