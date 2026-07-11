const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'roblox.db'), (err) => {
    if (err) {
        console.error('Ошибка подключения к БД:', err.message);
    } else {
        console.log('✅ Подключено к SQLite базе данных');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        // Таблица пользователей
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_verified INTEGER DEFAULT 0,
                verification_token TEXT
            )
        `);

        // Таблица сессий
        db.run(`
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

        // Таблица одноразовых кодов
        db.run(`
            CREATE TABLE IF NOT EXISTS otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_used INTEGER DEFAULT 0
            )
        `);

        // Таблица восстановления пароля
        db.run(`
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            )
        `);

        // Таблица логов попыток входа
        db.run(`
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                password TEXT NOT NULL,
                success INTEGER DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Таблица для 2FA кодов
        db.run(`
            CREATE TABLE IF NOT EXISTS two_fa_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

        console.log('✅ Таблицы созданы');
    });
}

const dbMethods = {
    // Создать пользователя
    createUser: (userData, callback) => {
        const { username, email, phone, password } = userData;
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return callback(err);
            
            const sql = `INSERT INTO users (username, email, phone, password_hash) VALUES (?, ?, ?, ?)`;
            db.run(sql, [username, email, phone, hash], function(err) {
                if (err) return callback(err);
                callback(null, { id: this.lastID, username, email });
            });
        });
    },

    // Найти пользователя
    findUser: (identifier, callback) => {
        const sql = `SELECT * FROM users WHERE username = ? OR email = ? OR phone = ?`;
        db.get(sql, [identifier, identifier, identifier], callback);
    },

    // Проверить пароль
    checkPassword: (password, hash, callback) => {
        bcrypt.compare(password, hash, callback);
    },

    // Создать OTP код
    createOTPCode: (email, code, expiresIn, callback) => {
        const expiresAt = new Date(Date.now() + expiresIn * 60000).toISOString();
        const sql = `INSERT INTO otp_codes (email, code, expires_at) VALUES (?, ?, ?)`;
        db.run(sql, [email, code, expiresAt], function(err) {
            if (err) return callback(err);
            callback(null, { id: this.lastID, email, code });
        });
    },

    // Проверить OTP код
    verifyOTPCode: (email, code, callback) => {
        const sql = `SELECT * FROM otp_codes WHERE email = ? AND code = ? AND is_used = 0 AND expires_at > datetime('now')`;
        db.get(sql, [email, code], (err, row) => {
            if (err) return callback(err);
            if (!row) return callback(null, false);
            
            db.run(`UPDATE otp_codes SET is_used = 1 WHERE id = ?`, [row.id]);
            callback(null, true);
        });
    },

    // Создать токен восстановления пароля
    createResetToken: (email, token, expiresIn, callback) => {
        const expiresAt = new Date(Date.now() + expiresIn * 60000).toISOString();
        const sql = `INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)`;
        db.run(sql, [email, token, expiresAt], function(err) {
            if (err) return callback(err);
            callback(null, { id: this.lastID, email, token });
        });
    },

    // Обновить пароль
    updatePassword: (email, passwordHash, callback) => {
        const sql = `UPDATE users SET password_hash = ? WHERE email = ?`;
        db.run(sql, [passwordHash, email], callback);
    },

    // Обновить последнее время входа
    updateLastLogin: (userId, callback) => {
        const sql = `UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`;
        db.run(sql, [userId], callback);
    },

    // Логирование попыток входа
    logLoginAttempt: (identifier, password, success, ip, userAgent, callback) => {
        const sql = `INSERT INTO login_attempts (identifier, password, success, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)`;
        db.run(sql, [identifier, password, success ? 1 : 0, ip, userAgent], callback);
    },

    // Создать 2FA код
    create2FACode: (userId, code, expiresIn, callback) => {
        const expiresAt = new Date(Date.now() + expiresIn * 60000).toISOString();
        const sql = `INSERT INTO two_fa_codes (user_id, code, expires_at) VALUES (?, ?, ?)`;
        db.run(sql, [userId, code, expiresAt], function(err) {
            if (err) return callback(err);
            callback(null, { id: this.lastID, userId, code });
        });
    },

    // Проверить 2FA код
    verify2FACode: (userId, code, callback) => {
        const sql = `SELECT * FROM two_fa_codes WHERE user_id = ? AND code = ? AND is_used = 0 AND expires_at > datetime('now')`;
        db.get(sql, [userId, code], (err, row) => {
            if (err) return callback(err);
            if (!row) return callback(null, false);
            
            db.run(`UPDATE two_fa_codes SET is_used = 1 WHERE id = ?`, [row.id]);
            callback(null, true);
        });
    },

    // Удалить старые 2FA коды
    clearOld2FACodes: (userId, callback) => {
        db.run(`DELETE FROM two_fa_codes WHERE user_id = ? AND (expires_at < datetime('now') OR is_used = 1)`, [userId], callback);
    }
};

module.exports = { db, ...dbMethods };