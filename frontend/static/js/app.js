/**
 * Secure Password Manager - Frontend Application
 * Handles all UI interactions and API calls
 */

// ============= GLOBAL STATE =============

let currentUser = null;
let accessToken = null;
let masterPassword = null; // Stored in memory during session
let allPasswords = [];
let currentPasswordId = null; // For edit mode

// ============= AUTHENTICATION =============

function showTab(tab) {
    // Switch between login and register tabs
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.auth-form').forEach(form => form.classList.remove('active'));
    
    if (tab === 'login') {
        document.querySelector('.tab-btn:first-child').classList.add('active');
        document.getElementById('login-form').classList.add('active');
    } else {
        document.querySelector('.tab-btn:last-child').classList.add('active');
        document.getElementById('register-form').classList.add('active');
    }
}

async function register() {
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;
    const errorDiv = document.getElementById('register-error');
    
    // Validation
    if (!email || !password || !confirm) {
        errorDiv.textContent = 'Please fill in all fields';
        return;
    }
    
    if (password !== confirm) {
        errorDiv.textContent = 'Passwords do not match';
        return;
    }
    
    if (password.length < 8) {
        errorDiv.textContent = 'Password must be at least 8 characters';
        return;
    }
    
    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: email,
                master_password: password
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            errorDiv.style.color = '#28a745';
            errorDiv.textContent = '✅ Account created! Please login.';
            setTimeout(() => showTab('login'), 2000);
        } else {
            errorDiv.textContent = data.detail || 'Registration failed';
        }
    } catch (error) {
        errorDiv.textContent = 'Network error. Please try again.';
        console.error('Register error:', error);
    }
}

async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const twoFAToken = document.getElementById('login-2fa').value;
    const errorDiv = document.getElementById('login-error');
    
    if (!email || !password) {
        errorDiv.textContent = 'Please fill in all fields';
        return;
    }
    
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: email,
                master_password: password,
                totp_token: twoFAToken || null
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Store credentials
            accessToken = data.access_token;
            currentUser = data.user;
            masterPassword = password; // Keep in memory for encryption
            
            // Show vault
            showVault();
        } else {
            if (response.status === 401 && response.headers.get('X-2FA-Required')) {
                // Show 2FA input
                document.getElementById('login-2fa-container').style.display = 'block';
                errorDiv.textContent = 'Please enter your 2FA code';
            } else {
                errorDiv.textContent = data.detail || 'Login failed';
            }
        }
    } catch (error) {
        errorDiv.textContent = 'Network error. Please try again.';
        console.error('Login error:', error);
    }
}

function logout() {
    // Clear all session data
    accessToken = null;
    currentUser = null;
    masterPassword = null;
    allPasswords = [];
    
    // Show auth page
    document.getElementById('vault-page').classList.remove('active');
    document.getElementById('auth-page').classList.add('active');
    
    // Clear forms
    document.getElementById('login-email').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('login-2fa').value = '';
}

// ============= VAULT MANAGEMENT =============

async function showVault() {
    // Hide auth, show vault
    document.getElementById('auth-page').classList.remove('active');
    document.getElementById('vault-page').classList.add('active');
    
    // Set user email
    document.getElementById('user-email').textContent = currentUser.email;
    
    // Load passwords and stats
    await loadPasswords();
    await loadStats();
}

async function loadPasswords() {
    try {
        const response = await fetch('/api/vault/passwords', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        if (response.ok) {
            allPasswords = await response.json();
            displayPasswords(allPasswords);
        } else {
            console.error('Failed to load passwords');
        }
    } catch (error) {
        console.error('Error loading passwords:', error);
    }
}

function displayPasswords(passwords) {
    const container = document.getElementById('passwords-container');
    
    if (passwords.length === 0) {
        container.innerHTML = '<p class="empty-message">No passwords yet. Click "Add Password" to get started!</p>';
        return;
    }
    
    container.innerHTML = passwords.map(pwd => `
        <div class="password-card ${pwd.is_compromised ? 'compromised' : ''}">
            ${pwd.is_favorite ? '<div style="position: absolute; top: 10px; right: 10px; font-size: 1.5em;">⭐</div>' : ''}
            ${pwd.is_compromised ? '<div style="color: #dc3545; font-weight: bold; margin-bottom: 10px;">⚠️ COMPROMISED</div>' : ''}
            
            <div class="website-name">${escapeHtml(pwd.website_name)}</div>
            <div class="username">${escapeHtml(pwd.username)}</div>
            <span class="category-badge">${pwd.category}</span>
            
            <div class="actions">
                <button class="btn-view" onclick="viewPassword(${pwd.id})">👁️ View</button>
                <button class="btn-edit" onclick="editPassword(${pwd.id})">✏️ Edit</button>
                <button class="btn-delete" onclick="deletePassword(${pwd.id})">🗑️ Delete</button>
            </div>
        </div>
    `).join('');
}

async function loadStats() {
    try {
        const response = await fetch('/api/vault/stats', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        if (response.ok) {
            const stats = await response.json();
            
            document.getElementById('total-passwords').textContent = stats.total_passwords;
            document.getElementById('weak-passwords').textContent = stats.weak_passwords;
            document.getElementById('compromised-passwords').textContent = stats.compromised_passwords;
            document.getElementById('favorite-passwords').textContent = stats.favorite_passwords;
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// ============= PASSWORD CRUD =============

function showAddPasswordModal() {
    currentPasswordId = null;
    document.getElementById('modal-title').textContent = 'Add Password';
    document.getElementById('password-form').reset();
    document.getElementById('password-modal').classList.add('active');
}

async function savePassword(event) {
    event.preventDefault();
    
    const passwordData = {
        website_name: document.getElementById('website-name').value,
        website_url: document.getElementById('website-url').value || null,
        username: document.getElementById('username').value,
        password: document.getElementById('password-field').value,
        category: document.getElementById('category').value,
        notes: document.getElementById('notes').value || null,
        is_favorite: document.getElementById('is-favorite').checked
    };
    
    try {
        let url = '/api/vault/passwords';
        let method = 'POST';
        
        if (currentPasswordId) {
            url = `/api/vault/passwords/${currentPasswordId}`;
            method = 'PUT';
        }
        
        const response = await fetch(`${url}?master_password=${encodeURIComponent(masterPassword)}`, {
            method: method,
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(passwordData)
        });
        
        if (response.ok) {
            closePasswordModal();
            await loadPasswords();
            await loadStats();
        } else {
            const error = await response.json();
            alert('Error: ' + (error.detail || 'Failed to save password'));
        }
    } catch (error) {
        console.error('Error saving password:', error);
        alert('Network error. Please try again.');
    }
}

async function viewPassword(id) {
    try {
        const response = await fetch(`/api/vault/passwords/${id}?master_password=${encodeURIComponent(masterPassword)}`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        if (response.ok) {
            const pwd = await response.json();
            
            // Show password in alert (you can create a better modal for this)
            alert(`Website: ${pwd.website_name}\nUsername: ${pwd.username}\nPassword: ${pwd.password}`);
            
            // Better UX: Copy to clipboard
            navigator.clipboard.writeText(pwd.password);
            alert('Password copied to clipboard!');
        } else {
            alert('Failed to decrypt password');
        }
    } catch (error) {
        console.error('Error viewing password:', error);
    }
}

async function editPassword(id) {
    try {
        const response = await fetch(`/api/vault/passwords/${id}?master_password=${encodeURIComponent(masterPassword)}`, {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        if (response.ok) {
            const pwd = await response.json();
            
            currentPasswordId = id;
            document.getElementById('modal-title').textContent = 'Edit Password';
            document.getElementById('website-name').value = pwd.website_name;
            document.getElementById('website-url').value = pwd.website_url || '';
            document.getElementById('username').value = pwd.username;
            document.getElementById('password-field').value = pwd.password;
            document.getElementById('category').value = pwd.category;
            document.getElementById('notes').value = pwd.notes || '';
            document.getElementById('is-favorite').checked = pwd.is_favorite;
            
            document.getElementById('password-modal').classList.add('active');
        }
    } catch (error) {
        console.error('Error loading password for edit:', error);
    }
}

async function deletePassword(id) {
    if (!confirm('Are you sure you want to delete this password?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/vault/passwords/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        if (response.ok) {
            await loadPasswords();
            await loadStats();
        } else {
            alert('Failed to delete password');
        }
    } catch (error) {
        console.error('Error deleting password:', error);
    }
}

// ============= PASSWORD GENERATOR =============

async function generatePasswordInModal() {
    const password = await generateNewPassword();
    if (password) {
        document.getElementById('password-field').value = password;
        await checkPasswordStrength(password);
    }
}

async function generateNewPassword() {
    const length = document.getElementById('password-length')?.value || 16;
    const useUppercase = document.getElementById('use-uppercase')?.checked !== false;
    const useLowercase = document.getElementById('use-lowercase')?.checked !== false;
    const useDigits = document.getElementById('use-digits')?.checked !== false;
    const useSymbols = document.getElementById('use-symbols')?.checked !== false;
    
    try {
        const response = await fetch('/api/utils/generate-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                length: parseInt(length),
                use_uppercase: useUppercase,
                use_lowercase: useLowercase,
                use_digits: useDigits,
                use_symbols: useSymbols
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            
            // Update display if in generator modal
            const display = document.getElementById('generated-password-display');
            if (display) {
                display.value = data.password;
                displayStrength(data.strength, 'generated-strength');
            }
            
            return data.password;
        }
    } catch (error) {
        console.error('Error generating password:', error);
    }
    
    return null;
}

async function checkPasswordStrength(password) {
    if (!password) return;
    
    try {
        const response = await fetch('/api/utils/check-strength', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: password })
        });
        
        if (response.ok) {
            const strength = await response.json();
            displayStrength(strength, 'password-strength-indicator');
        }
    } catch (error) {
        console.error('Error checking strength:', error);
    }
}

function displayStrength(strength, elementId) {
    const container = document.getElementById(elementId);
    if (!container) return;
    
    const colors = {
        'Weak': '#dc3545',
        'Fair': '#ffc107',
        'Good': '#17a2b8',
        'Strong': '#28a745'
    };
    
    container.innerHTML = `
        <div style="margin: 10px 0;">
            <div style="background: #f0f0f0; height: 8px; border-radius: 5px; overflow: hidden;">
                <div style="width: ${strength.score * 10}%; height: 100%; background: ${colors[strength.strength]}; transition: all 0.3s;"></div>
            </div>
            <div style="margin-top: 5px; color: ${colors[strength.strength]}; font-weight: bold;">
                ${strength.strength} - ${strength.crack_time}
            </div>
            <div style="font-size: 0.85em; color: #666; margin-top: 5px;">
                ${strength.feedback.join(', ')}
            </div>
        </div>
    `;
}

// ============= SEARCH & FILTER =============

function searchPasswords() {
    const searchTerm = document.getElementById('search-box').value.toLowerCase();
    const filtered = allPasswords.filter(pwd => 
        pwd.website_name.toLowerCase().includes(searchTerm) ||
        pwd.username.toLowerCase().includes(searchTerm)
    );
    displayPasswords(filtered);
}

function filterByCategory() {
    const category = document.getElementById('category-filter').value;
    const filtered = category ? 
        allPasswords.filter(pwd => pwd.category === category) : 
        allPasswords;
    displayPasswords(filtered);
}

// ============= MODAL CONTROLS =============

function closePasswordModal() {
    document.getElementById('password-modal').classList.remove('active');
    currentPasswordId = null;
}

function closeGeneratorModal() {
    document.getElementById('generator-modal').classList.remove('active');
}

function togglePasswordVisibility() {
    const field = document.getElementById('password-field');
    field.type = field.type === 'password' ? 'text' : 'password';
}

function copyGeneratedPassword() {
    const password = document.getElementById('generated-password-display').value;
    navigator.clipboard.writeText(password);
    alert('Password copied to clipboard!');
}

function updateLength() {
    const value = document.getElementById('password-length').value;
    document.getElementById('length-value').textContent = value;
}

// ============= SETTINGS (2FA) =============

function showSettings() {
    alert('Settings feature coming soon! This would include:\n- 2FA setup\n- Change master password\n- Export vault\n- Account settings');
}

// ============= UTILITIES =============

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============= INITIALIZATION =============

document.addEventListener('DOMContentLoaded', () => {
    console.log('🔐 Secure Password Manager loaded!');
    
    // Check password strength on input
    const passwordField = document.getElementById('password-field');
    if (passwordField) {
        passwordField.addEventListener('input', (e) => {
            checkPasswordStrength(e.target.value);
        });
    }
});