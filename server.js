require("dotenv").config();
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const nodemailer = require("nodemailer");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const path = require("path");
const fs = require("fs");
const { randomUUID } = require("crypto");
const bcrypt = require("bcrypt");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const fetch = require('node-fetch'); // لو مش مثبت: npm install node-fetch@2
const app = express(); 

const KEY = Buffer.from(process.env.ENCRYPTION_KEY); // 32 بايت
const IV_LENGTH = 16; // طول الـ IV للـ AES

// إعدادات التخزين المؤقت للملفات الثابتة   
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: "30d",
  immutable: true
}));

// أمان إضافي للرؤوس
app.use((req, res, next) => {
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});
const crypto = require("crypto");

const escapeHtml = (str = "") =>
  str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[m]));

// ------------------ CONFIG ------------------
const PORT = process.env.PORT || 3000;
const ADMIN_USER = "ELVI.ADMIN.SYSTEM";
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH;
const DATA_FILE = path.join(__dirname, "data.json");
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, "hex");
const ALGORITHM = 'aes-256-cbc';
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const CHAT_ID = process.env.CHAT_ID;


// Encryption functions for data.json
const encrypt = (text) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
};

const decrypt = (encryptedText) => {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encrypted = parts.join(':');
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

let db = {
    users: {}, products: [], contacts: [], support: [], settings: {
        sections: [], pages: {}, theme: { bg: '#0b0b0d', text: '#fff' },
        heroTitle: 'مرحبا بكم في Electron Vision', heroDescription: 'ثورة تقنية جديدة.'
    }
};
// تحميل قاعدة البيانات المشفرة
if (fs.existsSync(DATA_FILE)) {
    try {
        const encryptedData = fs.readFileSync(DATA_FILE, 'utf8');
        db = JSON.parse(decrypt(encryptedData));
    } catch (err) {
        console.error('Error decrypting data.json, using default db');
    }
} else {
    fs.writeFileSync(DATA_FILE, encrypt(JSON.stringify(db, null, 2)));
}


// ------------------ DATA VALIDATION ------------------
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};




// 🔧 ضمان سلامة بنية قاعدة البيانات
if (!Array.isArray(db.contacts)) db.contacts = [];
if (!Array.isArray(db.support)) db.support = [];
if (!Array.isArray(db.products)) db.products = [];
if (typeof db.users !== 'object' || db.users === null) db.users = {};
if (!db.settings) {
    db.settings = {
        sections: [],
        pages: {},
        theme: { bg: '#0b0b0d', text: '#fff' },
        heroTitle: '',
        heroDescription: ''
    };
}

const saveDB = () => {
    try {
        fs.writeFileSync(DATA_FILE, encrypt(JSON.stringify(db, null, 2)));
    } catch (err) {
        console.error('Error encrypting and saving data.json');
    }
};

// ------------------ INIT ------------------
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(session({
  name: "ev_session", // ← ثبّت الاسم
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24
  }
}));
app.use((req, res, next) => {
  const ua = (req.headers["user-agent"] || "").toLowerCase();

  const scanners = [
    "nikto",
    "sqlmap",
    "nmap",
    "acunetix",
    "dirbuster",
    "wpscanner",
    "havij",
    "fimap",
    "netsparker",
    "openvas",
    "nessus",
    "burpsuite"
  ];

  if (scanners.some(s => ua.includes(s))) {
    return res.status(404).end();
  }

  next();
});


app.use(limiter);   


const ADMIN_ROUTE = process.env.ADMIN_ROUTE;
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});







app.disable("x-powered-by");if (!ADMIN_ROUTE) {
  throw new Error("ADMIN_ROUTE is not defined");
}

app.get(ADMIN_ROUTE, adminLimiter, (req, res) => {
  if (!req.session || req.session.admin !== true) {
    return res.status(404).end();
  }

  res.setHeader("Cache-Control", "no-store");

  res.sendFile(
    path.join(__dirname, "private", "admin.html")
  );
});



// صفحة اللودر عند فتح الموقع
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'loader.html'));
    
});

// الصفحة الأساسية
app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));    


// Security middleware
// ======================= CSP مخصص للمشروع =======================
app.use(helmet({
 contentSecurityPolicy: {
  useDefaults: true,
  directives: {
    defaultSrc: ["'self'"],
    objectSrc: ["'none'"],

baseUri: ["'self'"] ,



    scriptSrc: [
  "'self'",
  "'unsafe-hashes'",
  "'strict-dynamic'"
],


    scriptSrcAttr: ["'unsafe-inline'"],

    styleSrc: [
      "'self'",
      "'unsafe-inline'",
      "https://fonts.googleapis.com"
    ],

    fontSrc: [
      "'self'",
      "https://fonts.gstatic.com",
      "data:"
    ],
imgSrc: [
  "'self'",
  "https:",
  "data:"
],


    mediaSrc: [
      "'self'",
      "data:"
    ],

    connectSrc: ["'self'"],
    frameAncestors: ["'none'"]
  }
},


  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: false,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  frameguard: { action: "deny" }
}));

app.use((req, res, next) => {
  res.removeHeader("Server");
  next();
});

app.set("trust proxy", 1);

const downloadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/private", (req, res) => {
  res.status(404).end();
});


// Rate limiters
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
});

const uploadDir = path.join(__dirname, "private", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const safeName = file.originalname.replace(ext, '').replace(/\s+/g, '_');
        const finalName = `${safeName}-${Date.now()}${ext}`;
        cb(null, finalName);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
  const allowedExt = [".png", ".jpg", ".jpeg", ".webp", ".pdf", ".zip", ".rar", ".7z"  , ".iso"];
  const ext = path.extname(file.originalname).toLowerCase();

  if (!allowedExt.includes(ext)) {
    return cb(new Error("ملف غير مسموح"));
  }

  // منع تنفيذ أي سكربت حتى لو انرفع بالغلط
  if (file.originalname.match(/\.(js|exe|sh|bat|cmd|php)$/i)) {
    return cb(new Error("ملف خطر"));
  }

  cb(null, true);
}

});

// ------------------ HELPERS ------------------
function isAdmin(req,res,next){ if(req.session.admin) return next(); res.status(401).json({ error:"غير مصرح" }); }
const transporter = nodemailer.createTransport({ service:"gmail", auth:{ user:process.env.MAIL_USER, pass:process.env.MAIL_PASS }});
const generateCode = ()=>Math.floor(100000+Math.random()*900000).toString();

// ------------------ AUTH ------------------
app.post("/admin-login", authLimiter, async(req,res)=>{
    const { username,password } = req.body;
    if(username!==ADMIN_USER) return res.json({ ok:false });
    const match = await bcrypt.compare(password,ADMIN_PASS_HASH);
    if(!match) return res.json({ ok:false });
req.session.regenerate(() => {
  req.session.admin = true;
  delete req.session.user;
  res.json({ ok: true });
});

});
app.post("/admin-logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
let adminClients = [];

app.get("/api/admin/events", isAdmin, (req, res) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    adminClients.push(res);

    req.on("close", () => {
        adminClients = adminClients.filter(c => c !== res);
    });
});

function notifyAdmins(type) {
    adminClients.forEach(res => {
        res.write(`data: ${JSON.stringify({ type })}\n\n`);
    });
}



// ------------------ PRODUCTS ------------------
app.get("/api/products", generalLimiter, (req,res)=>res.json(db.products));
app.post("/api/products", isAdmin, generalLimiter, upload.single("file"), (req,res)=>{
    const { name, description, price, type } = req.body;
    const product = { id:Date.now().toString(), name, description, type };
    if(type==="paid") product.price=Number(price)||0;
  if(req.file){
    product.file = req.file.filename;
    product.originalName = req.file.originalname; // مهم: الاسم الأصلي
}

    db.products.push(product);
    saveDB();
    res.json({ ok:true });
});
app.delete("/api/products/:id", isAdmin,(req,res)=>{
    db.products=db.products.filter(p=>p.id!=req.params.id);
    saveDB();
    res.json({ ok:true });
});

app.get("/download/:id", downloadLimiter, (req, res) => {
  const product = db.products.find(p => p.id === req.params.id);
  if (!product || !product.file) {
    return res.status(404).send("الملف غير موجود");
  }

  const filePath = path.join(uploadDir, product.file);
  const baseDir = path.resolve(uploadDir);
  const resolvedPath = path.resolve(filePath);

  if (!resolvedPath.startsWith(baseDir + path.sep)) {
    return res.status(403).send("Forbidden");
  }

  if (!fs.existsSync(resolvedPath)) {
    return res.status(404).send("File not found");
  }

  if (product.type === "paid" && !req.session.user) {
    return res.status(403).send("غير مصرح");
  }

  res.setHeader("X-Content-Type-Options", "nosniff");

  res.download(
    resolvedPath,
    product.originalName || path.basename(resolvedPath)
  );
});


// ------------------ SUPPORT ------------------
app.get("/api/support", isAdmin,(req,res)=>res.json(db.support));
app.post("/api/support",(req,res)=>{
    const { user, issue, details } = req.body;
    if(!user||!issue||!details) return res.status(400).json({ error:'جميع الحقول مطلوبة' });
    db.support.push({ id:Date.now().toString(), user, issue, details });
    saveDB();
        notifyAdmins("support");
    res.json({ ok:true });
});


app.delete("/api/support/:id", isAdmin, (req,res)=>{
    const { id } = req.params;
    const index = db.support.findIndex(s => s.id == id);
    if(index !== -1){
        db.support.splice(index,1);
        saveDB();
    }
    res.json({ ok:true });
});

// ------------------ CONTACT ------------------
app.get("/api/contact", (req, res) => {
    const formatted = db.contacts.map(c => ({
        id: c.id,
        name: c.name,
        email: c.contactType === 'email' ? c.contactValue : '',
        phone: c.contactType === 'phone' ? c.contactValue : '',
        message: c.message
    }));
    res.json(formatted);
});



app.delete("/api/contact/:id", isAdmin, (req,res)=>{
    const { id } = req.params;

    if (!Array.isArray(db.contacts)) {
        db.contacts = [];
    }

    const index = db.contacts.findIndex(c => c.id == id);
    if(index !== -1){
        db.contacts.splice(index,1);
        saveDB();
    }

    res.json({ ok:true });
});

app.post("/api/support/telegram", async (req,res) => {
    const { user, issue, details } = req.body;
    if(!user||!issue||!details) return res.status(400).json({ error:'جميع الحقول مطلوبة' });

    // تخزين الرسالة أولاً
    const newMsg = { id: Date.now().toString(), user, issue, details };
db.support.push(newMsg);
saveDB();
    notifyAdmins("support");
    // رسالة تيليجرام
    const msg = `🚨 رسالة دعم جديدة\n👤 المستخدم: ${user}\n⚠️ المشكلة: ${issue}\n📝 التفاصيل: ${details}`;
    try {
        await sendTelegramMessage(msg);
        res.json({ ok:true });
    } catch(err) {
        console.error("خطأ في إرسال تيليجرام:", err);
        res.status(500).json({ ok:false, error:"خطأ في إرسال الرسالة" });
    }
});
app.post("/api/contact/telegram", async (req, res) => {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
        return res.status(400).json({ error: "جميع الحقول مطلوبة" });
    }

    // Regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const phoneRegex = /^\+\d{7,15}$/;

    let contactType = "";
    let contactValue = email;

    if (emailRegex.test(email)) {
        contactType = "email";
    } else if (phoneRegex.test(email)) {
        contactType = "phone";
    } else {
        return res.status(400).json({
            error: "الرجاء إدخال بريد إلكتروني صحيح أو رقم هاتف يبدأ بـ +"
        });
    }

    // تأمين db.contacts
    if (!Array.isArray(db.contacts)) {
        db.contacts = [];
    }

    const newContact = {
        id: Date.now().toString(),
        name,
        contactType,   // 👈 جديد
        contactValue,  // 👈 جديد
        message
    };

    db.contacts.push(newContact);
saveDB();
    notifyAdmins("contact");


    // رسالة تيليجرام ذكية
    const msg = `💬 رسالة تواصل جديدة
👤 الاسم: ${name}
${contactType === "email" ? "✉️ الايميل" : "📱 الهاتف"}: ${contactValue}
📝 الرسالة: ${message}`;

    try {
        await sendTelegramMessage(msg);
        return res.json({ ok: true });
    } catch (err) {
        console.error("خطأ في إرسال تيليجرام:", err);
        return res.status(500).json({ ok: false, error: "خطأ في إرسال الرسالة" });
    }
});

// ------------------ USER AUTH ------------------
app.post("/register", async (req,res)=>{
    const { email, pass } = req.body;
    if(!email || !pass) return res.status(400).json({ ok:false, error:"البيانات ناقصة" });
    
    if(db.users[email]) return res.status(400).json({ ok:false, error:"المستخدم موجود مسبقاً" });
    
    const hashedPass = await bcrypt.hash(pass, 12);
    db.users[email] = { pass: hashedPass };
    saveDB();
    
    res.json({ ok:true });
});

const verificationCodes = {}; // { email: code }
app.post("/login", async (req, res) => {
  const { email, pass } = req.body;

  if (!email || !pass) {
    return res.status(400).json({
      ok: false,
      error: "البيانات ناقصة"
    });
  }

  const user = db.users[email];

  if (!user || !(await bcrypt.compare(pass, user.pass))) {
    return res.status(401).json({
      ok: false,
      error: "بيانات الدخول غير صحيحة"
    });
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({
        ok: false,
        error: "خطأ في الجلسة"
      });
    }

    req.session.user = email;

    return res.json({
      ok: true
    });
  });
});

// التحقق من حالة تسجيل الدخول
app.get("/auth/status", (req,res)=>{
    if(req.session.user) {
        const user = db.users[req.session.user] || {};
        res.json({ loggedIn:true, email:req.session.user, profile: user.profile || {} });
    } else {
        res.json({ loggedIn:false });
    }
});
const encryptField = (value) => {
  if (!value) return value;
  return encrypt(value);
};

const decryptField = (value) => {
  if (!value) return value;
  return decrypt(value);
};

// تحديث معلومات البروفايل
app.post("/profile/update", (req,res)=>{
    if(!req.session.user) return res.status(401).json({ ok:false, error:"غير مصرح" });
    
    const { name, bio, phone } = req.body;
    const email = req.session.user;
    
    if(!db.users[email]) db.users[email] = { pass: "" };
    if(!db.users[email].profile) db.users[email].profile = {};
    
    db.users[email].profile = { ...db.users[email].profile, name, bio, phone };
    saveDB();
    
    res.json({ ok:true });
});



// تسجيل الخروج
app.post("/logout", (req,res)=>{
    req.session.destroy((err)=>{
        if(err) return res.status(500).json({ ok:false, error:"خطأ في تسجيل الخروج" });
        res.json({ ok:true });
    });
});

app.post("/send", generalLimiter, [
    body('email').isEmail().normalizeEmail(),
    body('pass').isLength({ min: 6 }).trim().escape()
], async(req,res)=>{
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ ok: false, errors: errors.array() });
    }
    const { email, pass } = req.body;
    if(!email || !pass) return res.status(400).json({ ok:false });
    
    const code = Math.floor(100000+Math.random()*900000).toString();
    verificationCodes[email] = { code, pass };

    try{
        await transporter.sendMail({
            from: process.env.MAIL_USER,
            to: email,
            subject: "رمز التحقق",
            text: `رمز التحقق الخاص بك هو: ${code}`
        });
        res.json({ ok:true });
    } catch(e){
        console.error(e);
        res.json({ ok:false });
    }
});
app.post("/verify",async (req,res)=>{
    try {
        const { email, code } = req.body;
        if(!email || !code) return res.status(400).json({ ok:false, error:"البيانات ناقصة" });

        const data = verificationCodes[email];
        if(data && code.trim() === data.code){
            const hashedPass = await bcrypt.hash(data.pass, 12);
            db.users[email] = { pass: hashedPass };
            saveDB();
            delete verificationCodes[email];
            return res.json({ ok:true });
        }
        return res.status(400).json({ ok:false, error:"الكود غير صحيح" });
    } catch(err) {
        console.error("خطأ في التحقق:", err);
        return res.status(500).json({ ok:false, error:"خطأ داخلي في السيرفر" });
    }
});

// ------------------ THEME ------------------
app.get("/api/theme", isAdmin,(req,res)=>res.json(db.settings.theme));
app.post("/api/theme", isAdmin,(req,res)=>{
    const { bg,text } = req.body;
    db.settings.theme={ bg,text };
    saveDB();
    res.json({ ok:true });
});

// ------------------ HOMEPAGE ------------------
app.get("/api/homepage-data",(req,res)=>{
    res.json({
        heroTitle: db.settings.heroTitle,
        heroDescription: db.settings.heroDescription,
        sections: db.settings.sections
    });
});
app.post("/api/update-homepage-text", isAdmin,(req,res)=>{
    const { title, description } = req.body;
    if(title) db.settings.heroTitle=title;
    if(description) db.settings.heroDescription=description;
    saveDB();
    res.json({ ok:true });
});
app.post("/api/add-homepage-section", isAdmin,(req,res)=>{
    const { name } = req.body;
    if(!name) return res.status(400).json({ error:'اسم القسم مطلوب' });
    db.settings.sections.push({ title:name, content:'محتوى القسم' });
    saveDB();
    res.json({ ok:true });
});
app.post("/api/remove-homepage-section", isAdmin,(req,res)=>{
    const { name } = req.body;
    db.settings.sections=db.settings.sections.filter(s=>s.title!==name);
    saveDB();
    res.json({ ok:true });
});

// ------------------ DYNAMIC PAGES ------------------
app.post("/api/save-page", isAdmin, generalLimiter, (req, res) => {
    const { page, content } = req.body;
    if (!page || !content) return res.status(400).json({ error: 'صفحة أو محتوى فارغ' });
    db.settings.pages[page] = { content };
    saveDB();
    res.json({ ok: true });
});
app.get("/api/load-page/:page", isAdmin,(req,res)=>{
    const page = db.settings.pages?.[req.params.page];
    res.json(page || { content:'' });
});



// ------------------ STRIPE ------------------
app.post("/create-checkout-session", async(req,res)=>{
    try{
        const { product, price } = req.body;
        const unitPrice = Math.round(Number(price)*100);
        if(isNaN(unitPrice)||unitPrice<=0) return res.status(400).json({ error:"السعر غير صالح" });

        const sessionStripe = await stripe.checkout.sessions.create({
            payment_method_types:["card"],
            line_items:[{ price_data:{ currency:"usd", product_data:{ name:product }, unit_amount:unitPrice }, quantity:1 }],
            mode:"payment",
            success_url:"http://localhost:3000/success.html",
            cancel_url:"http://localhost:3000/cancel.html"
        });
        res.json({ url: sessionStripe.url });
    }catch(err){ console.error(err); res.status(500).json({ error:"حدث خطأ أثناء الدفع" }); }
});

// ------------------ STATIC ------------------
app.get("/page/:name", (req, res) => {
    const page = db.settings.pages?.[req.params.name];
    if (!page) return res.status(404).send('الصفحة غير موجودة');

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(`
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <title>${escapeHtml(req.params.name)}</title>
        </head>
        <body>
            ${escapeHtml(page.content)}
        </body>
        </html>
    `);
});



// ------------------ TELEGRAM ------------------




async function sendTelegramMessage(message) {
    try {
        const url = `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`;
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: CHAT_ID,
                text: message,
                parse_mode: 'HTML'
            })
        });
        const data = await res.json();
        return data.ok;
    } catch (err) {
        console.error("Telegram error:", err);
        return false;
    }
}
const compression = require("compression");
app.use(compression());


// ------------------ 404 HANDLER ------------------
app.use((req, res) => {
  if (req.path.startsWith("/api")) {
    return res.status(404).json({ error: "API route not found" });
  }
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

// ------------------ START SERVER ------------------
app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ error: "Server error" });
});

app.listen(PORT,()=>console.log(`🚀 Server running at http://localhost:${PORT}`));

// ------------------ END ------------------
