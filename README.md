# 🔐 Secure Password Manager

<div align="center">

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green.svg)
![Encryption](https://img.shields.io/badge/encryption-AES--256-red.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Enterprise-grade password manager with military-grade AES-256 encryption, PBKDF2 key derivation, breach detection, and 2FA support**

[Features](#-features) • [Security](#-security) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture)

</div>

---

## 🎯 Overview

A production-ready password manager built with security-first principles, featuring end-to-end encryption, zero-knowledge architecture, and comprehensive security measures. Your master password never leaves your device, and all passwords are encrypted using AES-256 before storage.

### ✨ Key Features

- 🔐 **AES-256 Encryption** - Military-grade encryption for all passwords
- 🔑 **PBKDF2 Key Derivation** - 100,000 iterations for master password protection
- 🛡️ **Zero-Knowledge Architecture** - Your master password never touches the server
- 🔒 **Bcrypt Password Hashing** - Secure master password storage
- 🚨 **Breach Detection** - HaveIBeenPwned API integration (ready)
- 📱 **2FA Support** - TOTP-based two-factor authentication
- 🎲 **Secure Password Generator** - Cryptographically secure random passwords
- 💪 **Password Strength Analysis** - Real-time strength checking with crack time estimation
- 📊 **Vault Statistics** - Track weak and compromised passwords
- ⭐ **Favorites & Categories** - Organize your passwords efficiently
- 🔍 **Search & Filter** - Quickly find what you need
- 📝 **Secure Notes** - Store additional information safely

---

## 🔒 Security Architecture

### Encryption Flow
```
User Input (Master Password)
        ↓
PBKDF2 (100,000 iterations + unique salt)
        ↓
Derived Encryption Key (256-bit)
        ↓
AES-256-CBC Encryption
        ↓
Encrypted Password Storage
```

### Key Security Features

**1. Zero-Knowledge Architecture**
- Master password never sent to server in plain text
- All encryption/decryption happens client-side or in secure backend
- Server cannot decrypt your passwords without your master password

**2. Defense in Depth**
- Master password: Bcrypt hashing with salt
- Encryption key: PBKDF2 with 100,000 iterations
- Passwords: AES-256-CBC with unique IV per entry
- Sessions: JWT tokens with expiration
- API: Rate limiting and request validation

**3. Cryptographic Standards**
- **AES-256**: NIST-approved symmetric encryption
- **PBKDF2**: NIST SP 800-132 compliant
- **Bcrypt**: Adaptive hashing with work factor
- **Secrets module**: Cryptographically secure randomness

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- pip3
- Linux/Mac (recommended) or Windows

### Installation

1. **Clone the repository:**
```bash
   git clone https://github.com/Arman-1337/secure-password-manager.git
   cd secure-password-manager
```

2. **Install dependencies:**
```bash
   pip3 install -r requirements.txt
```

3. **Run the application:**
```bash
   python3 run.py
```

4. **Access the app:**
   - Open browser: http://127.0.0.1:8000
   - API Documentation: http://127.0.0.1:8000/docs

---

## 📖 Usage

### 1. Register Your Account

- Navigate to http://127.0.0.1:8000
- Click "Register" tab
- Enter email and strong master password
- **CRITICAL:** Remember your master password - it cannot be recovered!

**Master Password Requirements:**
- Minimum 8 characters
- Uppercase and lowercase letters
- Numbers
- Special characters

### 2. Login

- Enter your credentials
- (Optional) Enter 2FA code if enabled

### 3. Add Password
```
1. Click "Add Password" button
2. Fill in details:
   - Website Name (e.g., "GitHub")
   - Website URL (optional)
   - Username/Email
   - Password (or generate one)
   - Category (General, Social, Finance, Work, Email)
   - Notes (optional)
   - Mark as favorite (optional)
3. Click "Save Password"
```

Your password is encrypted with AES-256 before storage!

### 4. View Password
```
1. Find your password entry
2. Click "View" button
3. Enter master password
4. Password is decrypted and shown
5. Automatically copied to clipboard
```

### 5. Generate Secure Password
```
1. In Add/Edit form, click dice icon 🎲
2. Adjust settings:
   - Length (8-64 characters)
   - Character types (uppercase, lowercase, digits, symbols)
3. Password is generated using cryptographically secure random
4. Strength is analyzed in real-time
```

---

## 🎨 Features Deep Dive

### Password Generator

- **Cryptographically Secure**: Uses `secrets` module (not `random`)
- **Customizable**: Length, character sets, symbols
- **Real-time Analysis**: Strength score, entropy, crack time estimation

### Password Strength Checker
```python
Score: 0-10
Strength: Weak / Fair / Good / Strong
Entropy: Bits of randomness
Crack Time: Estimated time to crack
Feedback: Specific recommendations
```

**Analysis includes:**
- Length checking
- Character variety (uppercase, lowercase, digits, symbols)
- Common pattern detection (12345, password, qwerty)
- Sequential character detection
- Repeated character detection
- Entropy calculation

### Breach Detection

Integration with **HaveIBeenPwned** API:
- Checks if password appears in known data breaches
- Uses k-Anonymity (only 5 chars of hash sent)
- Your password never leaves your system in plain text
- Flags compromised passwords in red

### Vault Statistics

- Total passwords stored
- Weak passwords count
- Compromised passwords count
- Favorite passwords
- Category distribution
- Recent activity tracking

---

## 🏗️ Architecture

### Tech Stack

**Backend:**
- FastAPI 0.104.1 (Modern async Python web framework)
- SQLAlchemy 2.0+ (ORM with SQLite)
- Cryptography 41.0.7 (AES-256 encryption)
- Passlib 1.7.4 (Bcrypt hashing)
- Python-JOSE 3.3.0 (JWT tokens)
- PyOTP 2.9.0 (2FA/TOTP)

**Frontend:**
- Vanilla JavaScript (No framework overhead)
- HTML5 + CSS3
- Chart.js (Future: statistics visualization)

**Security:**
- AES-256-CBC encryption
- PBKDF2 key derivation (100k iterations)
- Bcrypt password hashing
- JWT authentication
- CORS protection
- Request validation

### Database Schema
```sql
Users Table:
- id (primary key)
- email (unique)
- master_password_hash (bcrypt)
- salt (for PBKDF2)
- totp_secret (for 2FA)
- is_2fa_enabled
- created_at
- last_login
- is_active

PasswordEntries Table:
- id (primary key)
- user_id (foreign key)
- website_name
- website_url
- username
- encrypted_password (AES-256)
- category
- notes
- is_favorite
- is_compromised
- created_at
- updated_at
- last_used
```

### API Endpoints

**Authentication:**
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get JWT token
- `POST /api/auth/2fa/setup` - Generate 2FA QR code
- `POST /api/auth/2fa/enable` - Enable 2FA
- `POST /api/auth/2fa/disable` - Disable 2FA

**Password Vault:**
- `GET /api/vault/passwords` - List all passwords
- `POST /api/vault/passwords` - Create password entry
- `GET /api/vault/passwords/{id}` - Get (and decrypt) password
- `PUT /api/vault/passwords/{id}` - Update password entry
- `DELETE /api/vault/passwords/{id}` - Delete password entry
- `GET /api/vault/stats` - Get vault statistics

**Utilities:**
- `POST /api/utils/generate-password` - Generate secure password
- `POST /api/utils/check-strength` - Analyze password strength
- `POST /api/utils/check-breach` - Check HaveIBeenPwned

---

## 🔐 Security Best Practices

### For Users

1. **Choose a strong master password**
   - 16+ characters recommended
   - Mix of all character types
   - Avoid common words and patterns
   - Use a passphrase (e.g., "Correct-Horse-Battery-Staple-42!")

2. **Enable 2FA immediately**
   - Adds second layer of security
   - Protects even if master password is compromised

3. **Regular security audits**
   - Check for weak passwords
   - Replace compromised passwords
   - Update old passwords periodically

4. **Never share your master password**
   - Not even with IT support
   - No one needs it - it's zero-knowledge!

### For Developers

1. **Environment variables**
   - Never commit `.env` file
   - Use strong random `SECRET_KEY`
   - Rotate keys regularly

2. **Database security**
   - Use PostgreSQL in production (not SQLite)
   - Enable database encryption at rest
   - Regular backups with encryption

3. **HTTPS only**
   - Never run without SSL/TLS in production
   - Use Let's Encrypt for free certificates

4. **Rate limiting**
   - Prevent brute force attacks
   - Implement on login endpoints

5. **Security headers**
   - HSTS, CSP, X-Frame-Options
   - Already implemented in `main.py`

---

## 🧪 Testing

### Manual Testing

1. **Register & Login**
```bash
   # Test account creation
   curl -X POST http://localhost:8000/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","master_password":"SecurePass123!"}'
   
   # Test login
   curl -X POST http://localhost:8000/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","master_password":"SecurePass123!"}'
```

2. **Add Password**
```bash
   curl -X POST http://localhost:8000/api/vault/passwords?master_password=SecurePass123! \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"website_name":"GitHub","username":"user@email.com","password":"myGitHubPass123"}'
```

3. **Retrieve Password**
```bash
   curl -X GET http://localhost:8000/api/vault/passwords/1?master_password=SecurePass123! \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### API Documentation

Interactive API documentation available at:
- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

---

## 📁 Project Structure
```
secure-password-manager/
├── backend/
│   └── app/
│       ├── api/
│       │   ├── auth_routes.py      # Authentication endpoints
│       │   ├── vault_routes.py     # Password CRUD
│       │   ├── utils_routes.py     # Utilities
│       │   └── schemas.py          # Pydantic models
│       ├── models/
│       │   └── user.py             # Database models
│       ├── security/
│       │   ├── auth.py             # JWT & bcrypt
│       │   └── encryption.py       # AES-256 engine
│       ├── utils/
│       │   ├── password_checker.py # Strength analysis
│       │   └── breach_checker.py   # HaveIBeenPwned
│       ├── database/
│       │   └── connection.py       # SQLAlchemy setup
│       ├── config.py               # Settings
│       └── main.py                 # FastAPI app
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css          # Styles
│   │   └── js/
│   │       └── app.js             # Frontend logic
│   └── templates/
│       └── index.html             # Main UI
├── .env                           # Environment variables
├── .gitignore                     # Git ignore
├── requirements.txt               # Dependencies
├── run.py                         # Server launcher
└── README.md                      # This file
```

---

## ⚙️ Configuration

Create `.env` file in project root:
```env
# Security
SECRET_KEY=your-super-secret-key-change-this-in-production-make-it-very-long
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Session
SESSION_TIMEOUT_MINUTES=15

# Database
DATABASE_URL=sqlite:///./password_manager.db
```

**CRITICAL:** Change `SECRET_KEY` in production!

Generate secure key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

---

## 🚀 Deployment

### Production Checklist

- [ ] Change `SECRET_KEY` to random 64+ char string
- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable HTTPS (SSL/TLS certificates)
- [ ] Set up reverse proxy (Nginx)
- [ ] Enable rate limiting
- [ ] Set up monitoring and logging
- [ ] Regular database backups (encrypted)
- [ ] Use production ASGI server (Gunicorn/Uvicorn)
- [ ] Set up firewall rules
- [ ] Enable automatic security updates

### Docker Deployment (Future)
```bash
docker build -t secure-password-manager .
docker run -p 8000:8000 secure-password-manager
```

---

## 🛡️ Security Disclosure

Found a security vulnerability? Please email: **armantahir.1023@gmail.com**

**Please do NOT:**
- Open a public GitHub issue
- Share vulnerability details publicly
- Exploit the vulnerability

**We will:**
- Acknowledge within 48 hours
- Provide timeline for fix
- Credit you in security advisory (if desired)

---

## 📈 Roadmap

### Planned Features

- [ ] **Browser Extension** - Auto-fill passwords in browser
- [ ] **Mobile Apps** - iOS and Android native apps
- [ ] **Import/Export** - CSV, LastPass, 1Password formats
- [ ] **Password Sharing** - Encrypted sharing with other users
- [ ] **Password History** - Track password changes
- [ ] **Auto-lock** - Automatic session timeout
- [ ] **Biometric Auth** - Fingerprint/Face ID support
- [ ] **Emergency Access** - Trusted contact can request access
- [ ] **Dark Mode** - UI theme options
- [ ] **Multi-language** - Internationalization
- [ ] **Audit Logs** - Track all vault access
- [ ] **Self-hosted** - Docker compose setup
- [ ] **Cloud Sync** - Optional encrypted cloud backup

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

**Code Standards:**
- Follow PEP 8 for Python
- Add docstrings to functions
- Include tests for new features
- Update README if needed

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Arman Bin Tahir**

- 🔐 Cybersecurity Engineer
- 🐍 Security Software Developer
- 🎓 Computer Science @ UMT Lahore
- 💼 Security Research & Portfolio Development

**Connect:**
- 📧 Email: armantahir.1023@gmail.com
- 💼 LinkedIn: [linkedin.com/in/arman-tahir](https://www.linkedin.com/in/arman-tahir-1b79b52b7/)
- 🐙 GitHub: [github.com/Arman-1337](https://github.com/Arman-1337)

---

## 🙏 Acknowledgments

- **Cryptography.io** - Excellent Python cryptography library
- **FastAPI** - Modern, fast web framework
- **HaveIBeenPwned** - Troy Hunt's breach detection service
- **OWASP** - Security best practices and guidelines
- **NIST** - Cryptographic standards and recommendations

---

## ⚠️ Disclaimer

**For Educational and Personal Use**

This password manager is built with security best practices but:
- Perform your own security audit before production use
- Author not liable for data loss or security breaches
- Use at your own risk
- For critical passwords, consider established solutions (Bitwarden, 1Password)

**Security Notice:**
- Always use HTTPS in production
- Regular security audits recommended
- Keep dependencies updated
- Monitor for security advisories

---

## 📚 Resources

**Learn More About:**
- [AES Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [PBKDF2 Key Derivation](https://en.wikipedia.org/wiki/PBKDF2)
- [Bcrypt Password Hashing](https://en.wikipedia.org/wiki/Bcrypt)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made by [Arman Bin Tahir](https://github.com/Arman-1337)

**Securing passwords, one encryption at a time.**

</div>