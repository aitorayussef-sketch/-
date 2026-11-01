# // ============================================
// 🌍 WASSET AL-ALAM - API SERVER COMPLETE
// Backend API للإدارة الكاملة
// ============================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this';
const ADMIN_PASSWORD_HASH = '$2a$10$YourHashedPasswordHere'; // bcrypt hash

// ==================== MIDDLEWARE ====================
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 100, // 100 طلب
    message: { error: 'تم تجاوز الحد المسموح، يرجى الانتظار 15 دقيقة' }
});
app.use('/api/', limiter);

// Auth Middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'يجب تسجيل الدخول' });
    
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(403).json({ error: 'توكن غير صالح' });
    }
};

const requireAdmin = (req, res, next) => {
    if (!req.user?.isAdmin) {
        return res.status(403).json({ error: 'صلاحيات المسؤول مطلوبة' });
    }
    next();
};

// ==================== DATA STORE (JSON Files) ====================
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const DB = {
    products: path.join(DATA_DIR, 'products.json'),
    orders: path.join(DATA_DIR, 'orders.json'),
    users: path.join(DATA_DIR, 'users.json'),
    sellers: path.join(DATA_DIR, 'sellers.json'),
    analytics: path.join(DATA_DIR, 'analytics.json'),
    settings: path.join(DATA_DIR, 'settings.json'),
    logs: path.join(DATA_DIR, 'logs.json')
};

// Initialize files
Object.values(DB).forEach(file => {
    if (!fs.existsSync(file)) fs.writeFileSync(file, '[]');
});

const readDB = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const writeDB = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

// ==================== AUTH API ====================

// تسجيل الدخول
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    
    // Check admin
    if (username === 'admin') {
        const valid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        if (!valid) return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
        
        const token = jwt.sign({ username, isAdmin: true, role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, user: { username, role: 'admin', isAdmin: true } });
    }
    
    // Check seller
    const sellers = readDB(DB.sellers);
    const seller = sellers.find(s => s.username === username);
    if (seller && await bcrypt.compare(password, seller.password)) {
        const token = jwt.sign({ username, id: seller.id, isAdmin: false, role: 'seller' }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, user: { username, role: 'seller', id: seller.id } });
    }
    
    res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
});

// تسجيل بائع جديد
app.post('/api/auth/register-seller', async (req, res) => {
    const { username, password, email, storeName } = req.body;
    const sellers = readDB(DB.sellers);
    
    if (sellers.find(s => s.username === username)) {
        return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newSeller = {
        id: crypto.randomUUID(),
        username,
        email,
        storeName,
        password: hashedPassword,
        createdAt: new Date().toISOString(),
        isActive: true,
        productsCount: 0,
        totalSales: 0,
        rating: 0
    };
    
    sellers.push(newSeller);
    writeDB(DB.sellers, sellers);
    
    res.json({ message: 'تم إنشاء الحساب بنجاح', sellerId: newSeller.id });
});

// ==================== PRODUCTS API ====================

// جلب كل المنتجات (عام)
app.get('/api/products', (req, res) => {
    const products = readDB(DB.products);
    const { source, category, search, minPrice, maxPrice, sort } = req.query;
    
    let filtered = products.filter(p => p.isActive);
    
    if (source) filtered = filtered.filter(p => p.source === source);
    if (category) filtered = filtered.filter(p => p.category === category);
    if (search) filtered = filtered.filter(p => p.title.toLowerCase().includes(search.toLowerCase()));
    if (minPrice) filtered = filtered.filter(p => p.price >= parseFloat(minPrice));
    if (maxPrice) filtered = filtered.filter(p => p.price <= parseFloat(maxPrice));
    
    if (sort === 'price-asc') filtered.sort((a, b) => a.price - b.price);
    if (sort === 'price-desc') filtered.sort((a, b) => b.price - a.price);
    if (sort === 'rating') filtered.sort((a, b) => b.rating - a.rating);
    if (sort === 'newest') filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
    res.json({ count: filtered.length, products: filtered });
});

// جلب منتج واحد
app.get('/api/products/:id', (req, res) => {
    const products = readDB(DB.products);
    const product = products.find(p => p.id === req.params.id);
    if (!product) return res.status(404).json({ error: 'المنتج غير موجود' });
    res.json(product);
});

// إضافة منتج (بائع)
app.post('/api/products', authenticate, (req, res) => {
    const { title, description, price, originalPrice, source, category, affiliateLink, image } = req.body;
    
    const newProduct = {
        id: crypto.randomUUID(),
        title,
        description,
        price: parseFloat(price),
        originalPrice: parseFloat(originalPrice) || price,
        source,
        category,
        affiliateLink,
        image: image || '📦',
        rating: 0,
        reviewsCount: 0,
        salesCount: 0,
        sellerId: req.user.id,
        isActive: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };
    
    const products = readDB(DB.products);
    products.push(newProduct);
    writeDB(DB.products, products);
    
    // Update seller product count
    const sellers = readDB(DB.sellers);
    const seller = sellers.find(s => s.id === req.user.id);
    if (seller) {
        seller.productsCount++;
        writeDB(DB.sellers, sellers);
    }
    
    res.status(201).json({ message: 'تم إضافة المنتج', product: newProduct });
});

// تعديل منتج (بائع أو أدمن)
app.put('/api/products/:id', authenticate, (req, res) => {
    const products = readDB(DB.products);
    const idx = products.findIndex(p => p.id === req.params.id);
    
    if (idx === -1) return res.status(404).json({ error: 'المنتج غير موجود' });
    
    // Check ownership
    if (!req.user.isAdmin && products[idx].sellerId !== req.user.id) {
        return res.status(403).json({ error: 'لا تملك صلاحية تعديل هذا المنتج' });
    }
    
    products[idx] = { ...products[idx], ...req.body, updatedAt: new Date().toISOString() };
    writeDB(DB.products, products);
    
    res.json({ message: 'تم تحديث المنتج', product: products[idx] });
});

// حذف منتج
app.delete('/api/products/:id', authenticate, (req, res) => {
    const products = readDB(DB.products);
    const idx = products.findIndex(p => p.id === req.params.id);
    
    if (idx === -1) return res.status(404).json({ error: 'المنتج غير موجود' });
    
    if (!req.user.isAdmin && products[idx].sellerId !== req.user.id) {
        return res.status(403).json({ error: 'لا تملك صلاحية الحذف' });
    }
    
    products.splice(idx, 1);
    writeDB(DB.products, products);
    
    res.json({ message: 'تم حذف المنتج' });
});

// ==================== ORDERS API ====================

// إنشاء طلب
app.post('/api/orders', (req, res) => {
    const { items, customer, paymentMethod, currency, totalAmount } = req.body;
    
    const order = {
        id: 'ORD-' + Date.now(),
        items,
        customer,
        paymentMethod,
        currency,
        totalAmount,
        status: 'pending', // pending, paid, shipped, delivered, cancelled
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };
    
    const orders = readDB(DB.orders);
    orders.push(order);
    writeDB(DB.orders, orders);
    
    // Update analytics
    updateAnalytics('new_order', { amount: totalAmount, currency });
    
    // Send email notification
    sendEmail(customer.email, 'تأكيد طلبك', `تم استلام طلبك رقم ${order.id}`);
    
    res.status(201).json({ message: 'تم إنشاء الطلب', order });
});

// جلب الطلبات (أدمن أو بائع)
app.get('/api/orders', authenticate, (req, res) => {
    const orders = readDB(DB.orders);
    
    if (req.user.isAdmin) {
        return res.json({ count: orders.length, orders });
    }
    
    // Filter by seller products
    const products = readDB(DB.products);
    const sellerProducts = products.filter(p => p.sellerId === req.user.id).map(p => p.id);
    const sellerOrders = orders.filter(o => o.items.some(i => sellerProducts.includes(i.productId)));
    
    res.json({ count: sellerOrders.length, orders: sellerOrders });
});

// تحديث حالة الطلب
app.put('/api/orders/:id/status', authenticate, requireAdmin, (req, res) => {
    const { status } = req.body;
    const orders = readDB(DB.orders);
    const order = orders.find(o => o.id === req.params.id);
    
    if (!order) return res.status(404).json({ error: 'الطلب غير موجود' });
    
    order.status = status;
    order.updatedAt = new Date().toISOString();
    writeDB(DB.orders, orders);
    
    res.json({ message: 'تم تحديث الحالة', order });
});

// ==================== USERS API (ADMIN ONLY) ====================

app.get('/api/users', authenticate, requireAdmin, (req, res) => {
    const users = readDB(DB.users);
    res.json({ count: users.length, users });
});

app.get('/api/sellers', authenticate, requireAdmin, (req, res) => {
    const sellers = readDB(DB.sellers);
    const safeSellers = sellers.map(({ password, ...s }) => s);
    res.json({ count: safeSellers.length, sellers: safeSellers });
});

app.put('/api/sellers/:id/activate', authenticate, requireAdmin, (req, res) => {
    const sellers = readDB(DB.sellers);
    const seller = sellers.find(s => s.id === req.params.id);
    if (!seller) return res.status(404).json({ error: 'البائع غير موجود' });
    
    seller.isActive = req.body.isActive;
    writeDB(DB.sellers, sellers);
    res.json({ message: 'تم تحديث الحالة' });
});

// ==================== ANALYTICS API ====================

app.get('/api/analytics/dashboard', authenticate, requireAdmin, (req, res) => {
    const products = readDB(DB.products);
    const orders = readDB(DB.orders);
    const sellers = readDB(DB.sellers);
    
    const totalSales = orders.filter(o => o.status === 'paid' || o.status === 'shipped' || o.status === 'delivered')
        .reduce((sum, o) => sum + (o.totalAmount || 0), 0);
    
    const today = new Date().toISOString().split('T')[0];
    const todayOrders = orders.filter(o => o.createdAt.startsWith(today));
    
    const analytics = {
        overview: {
            totalProducts: products.length,
            totalOrders: orders.length,
            totalSellers: sellers.length,
            totalSales: totalSales.toFixed(2),
            todayOrders: todayOrders.length,
            todayRevenue: todayOrders.reduce((sum, o) => sum + (o.totalAmount || 0), 0).toFixed(2)
        },
        salesBySource: {
            amazon: orders.filter(o => o.items.some(i => i.source === 'amazon')).length,
            alibaba: orders.filter(o => o.items.some(i => i.source === 'alibaba')).length,
            shein: orders.filter(o => o.items.some(i => i.source === 'shein')).length
        },
        recentOrders: orders.slice(-10).reverse(),
        topProducts: products.sort((a, b) => (b.salesCount || 0) - (a.salesCount || 0)).slice(0, 5)
    };
    
    res.json(analytics);
});

// ==================== SETTINGS API ====================

app.get('/api/settings', authenticate, requireAdmin, (req, res) => {
    const settings = readDB(DB.settings);
    res.json(settings[0] || {});
});

app.put('/api/settings', authenticate, requireAdmin, (req, res) => {
    writeDB(DB.settings, [req.body]);
    res.json({ message: 'تم حفظ الإعدادات' });
});

// ==================== CURRENCY API ====================

app.get('/api/currency/rates', (req, res) => {
    // In production, fetch from external API
    const rates = {
        USD: 1, EUR: 0.92, GBP: 0.79, JPY: 150.5, CNY: 7.24,
        AED: 3.67, SAR: 3.75, EGP: 30.9, TRY: 30.5, INR: 83.1,
        BTC: 0.000015, ETH: 0.00028, USDT: 1
    };
    res.json({ base: 'USD', rates, updatedAt: new Date().toISOString() });
});

// ==================== AI RECOMMENDATIONS API ====================

app.get('/api/ai/recommendations', authenticate, (req, res) => {
    const products = readDB(DB.products);
    const orders = readDB(DB.orders);
    
    // Simple AI logic
    const trending = products.sort((a, b) => (b.salesCount || 0) - (a.salesCount || 0)).slice(0, 5);
    const highMargin = products.filter(p => p.originalPrice && ((p.originalPrice - p.price) / p.originalPrice > 0.3)).slice(0, 5);
    
    res.json({
        trending,
        highMargin,
        suggestion: 'زيادة أسعار المنتجات الإلكترونية بنسبة 5% قد يزيد الأرباح بنسبة 12%'
    });
});

// ==================== SECURITY & LOGS ====================

app.get('/api/security/logs', authenticate, requireAdmin, (req, res) => {
    const logs = readDB(DB.logs);
    res.json({ logs: logs.slice(-100) });
});

app.post('/api/security/report', (req, res) => {
    const { type, ip, userAgent, details } = req.body;
    
    const log = {
        id: crypto.randomUUID(),
        type, // 'suspicious', 'blocked', 'error', 'login_attempt'
        ip,
        userAgent,
        details,
        timestamp: new Date().toISOString()
    };
    
    const logs = readDB(DB.logs);
    logs.push(log);
    writeDB(DB.logs, logs);
    
    // Auto-block if too many suspicious
    const suspiciousCount = logs.filter(l => l.ip === ip && l.type === 'suspicious').length;
    if (suspiciousCount > 10) {
        // Add to blocklist
        const settings = readDB(DB.settings);
        if (!settings[0]) settings[0] = {};
        if (!settings[0].blockedIPs) settings[0].blockedIPs = [];
        settings[0].blockedIPs.push(ip);
        writeDB(DB.settings, settings);
    }
    
    res.json({ message: 'تم تسجيل التقرير' });
});

// ==================== HELPER FUNCTIONS ====================

function updateAnalytics(event, data) {
    const analytics = readDB(DB.analytics);
    analytics.push({ event, data, timestamp: new Date().toISOString() });
    writeDB(DB.analytics, analytics);
}

function sendEmail(to, subject, text) {
    // Configure your SMTP settings
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: 587,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
        }
    });
    
    transporter.sendMail({ from: '"وسيط العالم" <noreply@waset.com>', to, subject, text })
        .catch(err => console.error('Email error:', err));
}

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'خطأ في الخادم', message: process.env.NODE_ENV === 'development' ? err.message : 'Internal Server Error' });
});

app.use((req, res) => {
    res.status(404).json({ error: 'المسار غير موجود' });
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log(`🌍 وسيط العالم API يعمل على المنفذ ${PORT}`);
    console.log(`📡 Health Check: http://localhost:${PORT}/api/health`);
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString(), version: '1.0.0' });
});

module.exports = app;