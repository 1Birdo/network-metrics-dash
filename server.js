const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Pool } = require('pg');
const path = require('path');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const rateLimit = require('express-rate-limit');
const WebSocket = require('ws');
const crypto = require('crypto');
require('dotenv').config();
const fs = require('fs');
const https = require('https');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const paypal = require('@paypal/checkout-server-sdk');

// Initialize database connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Global data stores
const metricsHistory = new Map();
const activeClients = new Map();
const apiKeys = new Map();
const MAX_HISTORY_LENGTH = 100;

// Email transporter configuration
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Rate limiters
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 3,
    message: 'Too many contact attempts, please try again later'
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: async (req, res) => {
        if (req.headers['upgrade'] === 'websocket' &&
            req.headers['x-api-key'] &&
            req.headers['x-server-name']) {
            return 0; // No limit for WebSocket connections
        }
        if (req.user) {
            const sub = await SubscriptionDB.findByUserId(req.user.id);
            return sub ? parseInt(sub.api_access.split('/')[0]) : 100;
        }
        return 100;
    },
    message: 'API limit exceeded. Consider upgrading your plan.'
});

// SSL configuration
const sslOptions = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH),
    minVersion: 'TLSv1.3',
    ciphers: [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256'
    ].join(':'),
    honorCipherOrder: true,
    secureOptions: crypto.constants.SSL_OP_NO_TLSv1_2
};

// PayPal client configuration
const paypalClient = new paypal.core.PayPalHttpClient(
    process.env.NODE_ENV === 'production'
        ? new paypal.core.LiveEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET)
        : new paypal.core.SandboxEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET)
);

// Initialize Express app
const app = express();
const server = https.createServer(sslOptions, app);
const wss = new WebSocket.Server({ noServer: true });

// Database initialization functions
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                google_id VARCHAR(255) UNIQUE,
                github_id VARCHAR(255) UNIQUE,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITH TIME ZONE,
                role VARCHAR(20) NOT NULL DEFAULT 'user',
                account_status VARCHAR(20) NOT NULL DEFAULT 'active',
                current_subscription_id INTEGER
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS api_calls (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                called_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS subscription_plans (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) NOT NULL,
                monthly_price DECIMAL(10,2) NOT NULL,
                max_devices INT NOT NULL,
                api_access VARCHAR(50) NOT NULL,
                alert_types VARCHAR(255) NOT NULL,
                support_level VARCHAR(50) NOT NULL,
                data_retention_days INT NOT NULL,
                analytics_level VARCHAR(50) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS subscriptions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                plan_id INTEGER REFERENCES subscription_plans(id) NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                start_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                end_date TIMESTAMP WITH TIME ZONE,
                payment_provider VARCHAR(20) NOT NULL,
                payment_subscription_id VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS payments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                subscription_id INTEGER REFERENCES subscriptions(id) NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                currency VARCHAR(3) NOT NULL DEFAULT 'USD',
                payment_provider VARCHAR(20) NOT NULL,
                payment_id VARCHAR(255) NOT NULL,
                status VARCHAR(20) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS server_metrics (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                server_name VARCHAR(255) NOT NULL,
                cpu_percent DECIMAL(5,2),
                memory_percent DECIMAL(5,2),
                disk_percent DECIMAL(5,2),
                network_in BIGINT,
                network_out BIGINT,
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                server_name VARCHAR(255) NOT NULL,
                alert_type VARCHAR(50) NOT NULL,
                alert_message TEXT NOT NULL,
                alert_level VARCHAR(20) NOT NULL,
                is_resolved BOOLEAN DEFAULT false,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP WITH TIME ZONE
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS webhooks (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                url TEXT NOT NULL,
                event_types VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Insert default subscription plans
        await client.query(`
            INSERT INTO subscription_plans 
                (name, monthly_price, max_devices, api_access, alert_types, 
                 support_level, data_retention_days, analytics_level)
            VALUES 
                ('Starter', 0.00, 5, '1000/mo', 'email', 
                 'community_forum', 1, 'none'),
                ('Professional', 4.57, 15, '50000/mo', 'email,webhook', 
                 'priority_email', 7, 'basic'),
                ('Enterprise', 9.79, 100, '500000/mo', 'email,webhook,sms,slack', 
                 '24_7_priority', 30, 'advanced')
            ON CONFLICT (name) DO NOTHING;
        `);

        console.log('Database initialized successfully');
    } catch (err) {
        console.error('Error initializing database:', err);
    } finally {
        client.release();
    }
}

// Database operations
const UserDB = {
    async findById(id) {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        return result.rows[0];
    },
    async findByGoogleId(googleId) {
        const result = await pool.query('SELECT * FROM users WHERE google_id = $1', [googleId]);
        return result.rows[0];
    },
    async findByGithubId(githubId) {
        const result = await pool.query('SELECT * FROM users WHERE github_id = $1', [githubId]);
        return result.rows[0];
    },
    async create(userData) {
        const result = await pool.query(`
            INSERT INTO users (google_id, github_id, name, email, last_login) 
            VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP) RETURNING *`,
            [userData.googleId, userData.githubId, userData.name, userData.email]
        );
        return result.rows[0];
    },
    async updateLastLogin(userId) {
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [userId]);
    },
    async getApiCallsToday(userId) {
        const result = await pool.query(`
            SELECT COUNT(*) as count 
            FROM api_calls 
            WHERE user_id = $1 
            AND called_at >= CURRENT_DATE 
            AND called_at < CURRENT_DATE + INTERVAL '1 day'`,
            [userId]
        );
        return parseInt(result.rows[0].count);
    },
    async getApiUsage(userId) {
        const result = await pool.query(`
            SELECT 
                COUNT(*) as current_month_api_calls,
                (SELECT COUNT(*) FROM api_calls 
                 WHERE user_id = $1 
                 AND called_at >= CURRENT_DATE 
                 AND called_at < CURRENT_DATE + INTERVAL '1 day') as today_calls
            FROM api_calls 
            WHERE user_id = $1 
            AND called_at >= DATE_TRUNC('month', CURRENT_DATE)`,
            [userId]
        );
        return result.rows[0];
    },
    async logApiCall(userId) {
        await pool.query(
            'INSERT INTO api_calls (user_id) VALUES ($1)',
            [userId]
        );
    },
    async getUserActivity(userId, shouldLog = true) {
        if (shouldLog) await this.logApiCall(userId);
        const result = await pool.query(`
            SELECT 
                last_login,
                (SELECT COUNT(*) FROM api_calls 
                 WHERE user_id = users.id 
                 AND called_at >= CURRENT_DATE 
                 AND called_at < CURRENT_DATE + INTERVAL '1 day') as today_calls
            FROM users 
            WHERE id = $1`,
            [userId]
        );
        return result.rows[0];
    }
};

const SubscriptionDB = {
    async findByUserId(userId) {
        const result = await pool.query(`
            SELECT s.*, p.name as plan_name, p.monthly_price, p.max_devices, p.api_access, 
                   p.alert_types, p.support_level, p.data_retention_days, p.analytics_level 
            FROM subscriptions s
            JOIN subscription_plans p ON s.plan_id = p.id
            WHERE s.user_id = $1 AND s.status = 'active'
            ORDER BY s.created_at DESC
            LIMIT 1
        `, [userId]);
        return result.rows[0];
    },
    async createSubscription(userId, planId, paymentProvider, paymentSubscriptionId) {
        const result = await pool.query(`
            INSERT INTO subscriptions 
                (user_id, plan_id, payment_provider, payment_subscription_id)
            VALUES ($1, $2, $3, $4)
            RETURNING *
        `, [userId, planId, paymentProvider, paymentSubscriptionId]);

        await pool.query(`
            UPDATE users SET current_subscription_id = $1
            WHERE id = $2
        `, [result.rows[0].id, userId]);

        return result.rows[0];
    },
    async cancelSubscription(subscriptionId) {
        const result = await pool.query(`
            UPDATE subscriptions 
            SET status = 'cancelled', end_date = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
            RETURNING *
        `, [subscriptionId]);
        return result.rows[0];
    },
    async getAllPlans() {
        const result = await pool.query(`
            SELECT * FROM subscription_plans
            ORDER BY monthly_price ASC
        `);
        return result.rows;
    },
    async getPlanById(planId) {
        const result = await pool.query(`
            SELECT * FROM subscription_plans
            WHERE id = $1
        `, [planId]);
        return result.rows[0];
    }
};

const PaymentDB = {
    async recordPayment(userId, subscriptionId, amount, currency, paymentProvider, paymentId, status) {
        const result = await pool.query(`
            INSERT INTO payments
                (user_id, subscription_id, amount, currency, payment_provider, payment_id, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
        `, [userId, subscriptionId, amount, currency, paymentProvider, paymentId, status]);
        return result.rows[0];
    },
    async getPaymentHistory(userId) {
        const result = await pool.query(`
            SELECT p.*, s.plan_id, sp.name as plan_name
            FROM payments p
            JOIN subscriptions s ON p.subscription_id = s.id
            JOIN subscription_plans sp ON s.plan_id = sp.id
            WHERE p.user_id = $1
            ORDER BY p.created_at DESC
        `, [userId]);
        return result.rows;
    }
};

const AdminDB = {
    async getUserStats() {
        const result = await pool.query(`
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN created_at >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as new_users_30d,
                COUNT(CASE WHEN last_login >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as active_users_7d
            FROM users
        `);
        return result.rows[0];
    },
    async getSubscriptionStats() {
        const result = await pool.query(`
            SELECT 
                sp.name as plan_name,
                COUNT(s.id) as total_subscriptions,
                SUM(sp.monthly_price) as monthly_revenue
            FROM subscriptions s
            JOIN subscription_plans sp ON s.plan_id = sp.id
            WHERE s.status = 'active'
            GROUP BY sp.name, sp.monthly_price
            ORDER BY sp.monthly_price ASC
        `);
        return result.rows;
    },
    async getApiUsageStats() {
        const result = await pool.query(`
            SELECT 
                DATE_TRUNC('day', called_at) as day,
                COUNT(*) as api_calls
            FROM api_calls
            WHERE called_at >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY day
            ORDER BY day ASC
        `);
        return result.rows;
    },
    async getAllUsers(limit = 50, offset = 0, search = '') {
        let query = `
            SELECT u.id, u.name, u.email, u.created_at, u.last_login, 
                   u.role, u.account_status, u.google_id, u.github_id,
                   sp.name as plan_name, sp.monthly_price
            FROM users u
            LEFT JOIN subscriptions s ON u.current_subscription_id = s.id
            LEFT JOIN subscription_plans sp ON s.plan_id = sp.id
        `;
        const params = [];
        if (search) {
            query += ` WHERE u.name ILIKE $1 OR u.email ILIKE $1 `;
            params.push(`%${search}%`);
        }
        query += ` ORDER BY u.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
        params.push(limit, offset);
        const result = await pool.query(query, params);
        return result.rows;
    },
    async getUserCount(search = '') {
        let query = `SELECT COUNT(*) FROM users`;
        const params = [];
        if (search) {
            query += ` WHERE name ILIKE $1 OR email ILIKE $1`;
            params.push(`%${search}%`);
        }
        const result = await pool.query(query, params);
        return parseInt(result.rows[0].count);
    },
    async promoteToAdmin(userId) {
        const result = await pool.query(`
            UPDATE users SET role = 'admin'
            WHERE id = $1
            RETURNING *
        `, [userId]);
        return result.rows[0];
    },
    async updateUserStatus(userId, status) {
        const result = await pool.query(`
            UPDATE users SET account_status = $2
            WHERE id = $1
            RETURNING *
        `, [userId, status]);
        return result.rows[0];
    }
};

// Initialize database
initializeDatabase().catch(err => console.error('Database initialization failed:', err));

// Express middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' },
}));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",
                'https://js.stripe.com',
                'https://cdn.tailwindcss.com',
                'https://cdnjs.cloudflare.com',
                'https://cdn.jsdelivr.net',
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                'https://cdn.tailwindcss.com',
                'https://cdnjs.cloudflare.com',
                'https://fonts.googleapis.com',
                'https://cdn.jsdelivr.net',
            ],
            fontSrc: [
                "'self'",
                'https://fonts.gstatic.com',
                'https://cdnjs.cloudflare.com',
                'https://cdn.jsdelivr.net',
            ],
            imgSrc: [
                "'self'",
                'data:',
                'https://fastly.picsum.photos',
            ],
            connectSrc: ["'self'", 'https://js.stripe.com'],
            frameSrc: ["'self'", 'https://js.stripe.com'],
        },
    },
    dnsPrefetchControl: { allow: true },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    xssFilter: true,
}));

app.use(cors());
app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback",
    scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || null;
        if (!email) return done(new Error('No email found in profile'), null);

        let user = await UserDB.findByGoogleId(profile.id);
        if (!user) {
            user = await UserDB.create({
                googleId: profile.id,
                name: profile.displayName,
                email: email
            });
        } else {
            await UserDB.updateLastLogin(user.id);
        }
        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
}));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "/auth/github/callback",
    scope: ['user:email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let email = profile.emails?.[0]?.value;
        if (!email) {
            const res = await fetch('https://api.github.com/user/emails', {
                headers: { Authorization: `token ${accessToken}` }
            });
            const emails = await res.json();
            email = emails.find(e => e.primary && e.verified)?.email;
        }
        if (!email) return done(new Error('No email found in profile'), null);

        let user = await UserDB.findByGithubId(profile.id);
        if (!user) {
            user = await UserDB.create({
                githubId: profile.id,
                name: profile.displayName || profile.username,
                email: email
            });
        } else {
            await UserDB.updateLastLogin(user.id);
        }
        done(null, user);
    } catch (err) {
        done(err, null);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await UserDB.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Helper functions
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') return next();
    res.status(403).render('403', { error: { status: 403, message: 'Admin access required' } });
}

function generateApiKey(userId) {
    const apiKey = crypto.randomBytes(32).toString('hex');
    apiKeys.set(apiKey, userId);
    return apiKey;
}

function validateApiKey(apiKey) {
    return apiKeys.has(apiKey);
}

async function checkSubscriptionLimits(req, res, next) {
    if (!req.isAuthenticated()) return res.redirect('/');
    try {
        const subscription = await SubscriptionDB.findByUserId(req.user.id);
        const servers = Array.from(activeClients.values())
            .filter(data => data.userId.toString() === req.user.id.toString());
            
        if (req.path === '/dashboard') {
            req.subscription = subscription || { plan_name: 'Starter', max_devices: 5 };
            return next();
        }
        
        if (servers.length >= (subscription?.max_devices || 5)) {
            return res.status(403).render('upgrade', { 
                message: 'Device limit reached. Please upgrade your plan.',
                subscription: subscription,
                currentDevices: servers.length
            });
        }
        
        req.subscription = subscription || { plan_name: 'Starter', max_devices: 5 };
        next();
    } catch (err) {
        console.error('Error checking subscription:', err);
        next();
    }
}

function updateServerMetrics(serverName, userId, metrics) {
    if (!metricsHistory.has(serverName)) {
        metricsHistory.set(serverName, []);
    }
    
    const timestamp = Date.now();
    const serverMetrics = { timestamp, metrics };
    
    const history = metricsHistory.get(serverName);
    history.push(serverMetrics);
    
    if (history.length > MAX_HISTORY_LENGTH) {
        history.shift();
    }
    
    activeClients.set(serverName, {
        userId: userId,
        serverName: serverName,
        lastUpdate: timestamp,
        metrics: history
    });
    
    // Check for alert conditions
    checkForAlerts(userId, serverName, metrics);
}

async function checkForAlerts(userId, serverName, metrics) {
    const subscription = await SubscriptionDB.findByUserId(userId);
    if (!subscription) return;
    
    // CPU alert
    if (metrics.cpu_percent > 90) {
        await triggerAlert(
            userId, 
            serverName, 
            'cpu', 
            `High CPU usage detected: ${metrics.cpu_percent}%`,
            'critical'
        );
    } else if (metrics.cpu_percent > 80) {
        await triggerAlert(
            userId, 
            serverName, 
            'cpu', 
            `Elevated CPU usage detected: ${metrics.cpu_percent}%`,
            'warning'
        );
    }
    
    // Memory alert
    if (metrics.memory_percent > 90) {
        await triggerAlert(
            userId, 
            serverName, 
            'memory', 
            `High memory usage detected: ${metrics.memory_percent}%`,
            'critical'
        );
    }
    
    // Disk alert
    if (metrics.disk_percent > 90) {
        await triggerAlert(
            userId, 
            serverName, 
            'disk', 
            `Low disk space detected: ${100 - metrics.disk_percent}% remaining`,
            'critical'
        );
    }
}

async function triggerAlert(userId, serverName, alertType, alertMessage, alertLevel = 'warning') {
    try {
        const subscription = await SubscriptionDB.findByUserId(userId);
        const supportedAlerts = subscription.alert_types.split(',');
        
        if (!supportedAlerts.includes(alertType)) return;
        
        await pool.query(`
            INSERT INTO alerts 
                (user_id, server_name, alert_type, alert_message, alert_level)
            VALUES ($1, $2, $3, $4, $5)
        `, [userId, serverName, alertType, alertMessage, alertLevel]);
        
        if (supportedAlerts.includes('email')) {
            await sendEmailAlert(userId, serverName, alertMessage);
        }
        
        if (supportedAlerts.includes('webhook')) {
            await triggerWebhooks(userId, {
                server: serverName,
                type: alertType,
                message: alertMessage,
                level: alertLevel,
                timestamp: new Date().toISOString()
            });
        }
    } catch (error) {
        console.error('Error triggering alert:', error);
    }
}

async function sendEmailAlert(userId, serverName, message) {
    const user = await UserDB.findById(userId);
    if (!user) return;

    const mailOptions = {
        from: `"Alert System" <${process.env.SMTP_FROM}>`,
        to: user.email,
        subject: `Alert for ${serverName}`,
        html: `
            <h2 style="color: #dc2626;">Alert Notification</h2>
            <p><strong>Server:</strong> ${serverName}</p>
            <p><strong>Message:</strong> ${message}</p>
            <p><strong>Timestamp:</strong> ${new Date().toLocaleString()}</p>
            <p style="margin-top: 1rem;">
                <a href="${process.env.BASE_URL}/dashboard" style="color: #2563eb;">View Dashboard</a>
            </p>
        `
    };

    await transporter.sendMail(mailOptions);
}

async function triggerWebhooks(userId, payload) {
    const webhooks = await pool.query(`
        SELECT * FROM webhooks 
        WHERE user_id = $1 AND is_active = true
    `, [userId]);

    for (const webhook of webhooks.rows) {
        const eventTypes = webhook.event_types.split(',');
        if (eventTypes.includes(payload.type)) {
            fetch(webhook.url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).catch(err => console.error('Webhook failed:', err));
        }
    }
}

async function getServerStats(user) {
    const userServers = [];
    for (const [clientId, data] of activeClients.entries()) {
        if (data.userId.toString() === user.id.toString()) {
            userServers.push({
                name: data.serverName,
                lastUpdate: data.lastUpdate,
                metrics: data.metrics[data.metrics.length - 1]?.metrics || {},
                isOnline: (Date.now() - data.lastUpdate) < 8000
            });
        }
    }
    return userServers;
}

function calculateAverages(servers) {
    let totalCpu = 0;
    let totalMemory = 0;
    let totalDisk = 0;
    let serversWithMetrics = 0;

    servers.forEach(server => {
        if (server.metrics) {
            serversWithMetrics++;
            totalCpu += server.metrics.cpu_percent ?? 0;
            totalMemory += server.metrics.memory_percent ?? 0;
            totalDisk += server.metrics.disk_percent ?? 0;
        }
    });

    return {
        cpu: serversWithMetrics ? Math.round(totalCpu / serversWithMetrics) : 0,
        memory: serversWithMetrics ? Math.round(totalMemory / serversWithMetrics) : 0,
        disk: serversWithMetrics ? Math.round(totalDisk / serversWithMetrics) : 0
    };
}

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/pricing', async (req, res) => {
    const plans = await SubscriptionDB.getAllPlans();
    res.render('pricing', { 
        user: req.user,
        plans,
        isLoggedIn: req.isAuthenticated()
    });
});

app.get('/dashboard', ensureAuthenticated, checkSubscriptionLimits, async (req, res) => {
    try {
        const servers = await getServerStats(req.user);
        const userActivity = await UserDB.getUserActivity(req.user.id, false);
        const subscription = await SubscriptionDB.findByUserId(req.user.id);
        const averages = calculateAverages(servers);
        
        const analyticsLevel = subscription?.analytics_level || 'none';
        let historicalData = [];
        let alertHistory = [];
        
        if (analyticsLevel !== 'none') {
            historicalData = await pool.query(`
                SELECT 
                    DATE_TRUNC('hour', timestamp) as hour,
                    AVG(cpu_percent) as avg_cpu,
                    AVG(memory_percent) as avg_memory,
                    AVG(disk_percent) as avg_disk
                FROM server_metrics
                WHERE user_id = $1 AND timestamp >= NOW() - INTERVAL '24 hours'
                GROUP BY hour
                ORDER BY hour ASC
            `, [req.user.id]);
        }
        
        if (analyticsLevel === 'advanced') {
            alertHistory = await pool.query(`
                SELECT * FROM alerts
                WHERE user_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
                ORDER BY created_at DESC
                LIMIT 10
            `, [req.user.id]);
        }
        
        res.render('dashboard', { 
            user: req.user,
            servers,
            activity: userActivity,
            subscription,
            averages,
            historicalData: historicalData.rows,
            alertHistory: alertHistory.rows,
            analyticsLevel
        });
    } catch (error) {
        console.error('Error loading dashboard:', error);
        res.status(500).send('Error loading dashboard');
    }
});

// API Endpoints
app.post('/api/sdk/python', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || !validateApiKey(apiKey)) {
            return res.status(401).json({ error: 'Invalid API key' });
        }
        
        const userId = apiKeys.get(apiKey);
        const user = await UserDB.findById(userId);
        
        if (!user || user.account_status !== 'active') {
            return res.status(403).json({ error: 'Account not active' });
        }
        
        const { server_name, metrics } = req.body;
        if (!server_name || !metrics) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const subscription = await SubscriptionDB.findByUserId(userId);
        const userServers = Array.from(activeClients.values())
            .filter(data => data.userId.toString() === userId.toString());
            
        if (userServers.length >= (subscription?.max_devices || 5) && 
            !userServers.some(s => s.serverName === server_name)) {
            return res.status(403).json({ 
                error: `Device limit reached (${subscription?.max_devices || 5}). Please upgrade your plan.`
            });
        }
        
        updateServerMetrics(server_name, userId, metrics);
        await UserDB.logApiCall(userId);
        
        res.json({ status: 'Metrics received' });
    } catch (error) {
        console.error('Error processing Python SDK request:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/metrics/:serverName', ensureAuthenticated, async (req, res) => {
    try {
        const { serverName } = req.params;
        const serverData = activeClients.get(serverName);
        
        if (!serverData || serverData.userId.toString() !== req.user.id.toString()) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        const isOnline = (Date.now() - serverData.lastUpdate) < 8000;
        const latestMetrics = serverData.metrics[serverData.metrics.length - 1] || {};
        
        res.json({
            name: serverName,
            isOnline,
            lastUpdate: serverData.lastUpdate,
            metrics: latestMetrics.metrics || {}
        });
    } catch (error) {
        console.error('Error fetching metrics:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// WebSocket handling
wss.on('connection', (ws, request) => {
    const apiKey = request.headers['x-api-key'];
    const serverName = request.headers['x-server-name'];
    
    if (!apiKey || !validateApiKey(apiKey)) {
        ws.close(4001, 'Invalid API Key');
        return;
    }
    
    const userId = apiKeys.get(apiKey);
    
    UserDB.findById(userId)
        .then(async user => {
            if (!user) {
                ws.close(4001, 'User not found');
                return;
            }
            
            if (user.account_status !== 'active') {
                ws.close(4003, 'Account is suspended');
                return;
            }
            
            const subscription = await SubscriptionDB.findByUserId(userId);
            const maxDevices = subscription?.max_devices || 5;
                
            const userServers = Array.from(activeClients.values())
                .filter(data => data.userId.toString() === userId.toString());
                
            if (userServers.length >= maxDevices && !userServers.some(s => s.serverName === serverName)) {
                ws.close(4002, `Device limit reached (${maxDevices}). Please upgrade your plan.`);
                return;
            }
            
            console.log(`New client connected: ${serverName} (User: ${user.email})`);
            
            ws.isAlive = true;
            ws.on('pong', () => { ws.isAlive = true; });
            
            ws.on('message', async (message) => {
                try {
                    const data = JSON.parse(message);
                    if (data.type === 'metrics') {
                        const currentUser = await UserDB.findById(userId);
                        if (!currentUser || currentUser.account_status !== 'active') {
                            ws.close(4003, 'Account is suspended or not found');
                            return;
                        }
                        
                        updateServerMetrics(serverName, userId, data.data);
                        await UserDB.logApiCall(userId);
                        ws.send(JSON.stringify({ status: "Metrics received" }));
                    }
                } catch (err) {
                    console.error('Error processing message:', err);
                    ws.send(JSON.stringify({ error: "Invalid request" }));
                }
            });
            
            ws.on('close', () => {
                console.log(`Connection closed: ${serverName}`);
                activeClients.delete(serverName);
            });
        })
        .catch(err => {
            console.error('Database error during connection:', err);
            ws.close(500, 'Internal server error');
        });
});

// WebSocket upgrade handler
server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

// Start server
const PORT = process.env.PORT || 443;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Error handling
app.use((err, req, res, next) => {
    console.error(`Error ${err.status || 500}: ${err.message}`);
    const status = err.status || 500;
    const message = status === 500 ? 'Internal Server Error' : err.message;
    res.status(status).render(`${status}`, {
        error: {
            status: status,
            message: process.env.NODE_ENV === 'production' && status === 500 
                ? 'Something went wrong!'
                : message
        }
    });
});

app.use((req, res) => {
    res.status(404).render('404');
});

module.exports = app;