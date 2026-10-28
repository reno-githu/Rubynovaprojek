const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@rubynova.local";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12 ||
    !SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    "Jalankan aplikasi dengan ADMIN_PASSWORD (min. 12 karakter) dan SESSION_SECRET (min. 32 karakter)."
  );
}

// Inisialisasi Database SQLite3 (Memory / File)
const db = new sqlite3.Database(":memory:", (err) => {
  if (err) console.error("Gagal membuka database:", err.message);
  else console.log("Database SQLite3 berhasil dikoneksikan.");
});

// Pembuatan Tabel Database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    coins INTEGER NOT NULL DEFAULT 0 CHECK(coins >= 0),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS deposits (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL CHECK(amount BETWEEN 20000 AND 20000000),
    coins INTEGER NOT NULL,
    reference TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    reviewed_by INTEGER,
    note TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    delta INTEGER NOT NULL,
    type TEXT NOT NULL,
    reference TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    price INTEGER NOT NULL CHECK(price >= 0),
    active INTEGER NOT NULL DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    price INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS vip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    tier TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor INTEGER,
    action TEXT NOT NULL,
    reference TEXT,
    details TEXT DEFAULT '{}',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // Inisialisasi Akun Admin
  db.get("SELECT id FROM users WHERE email=?", [ADMIN_EMAIL.toLowerCase()], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
      db.run("INSERT INTO users(email,password_hash,role) VALUES(?,?,'admin')", [ADMIN_EMAIL.toLowerCase(), hash]);
    }
  });
});

const tiers = [
  ["VIP Bronze", 10000],
  ["VIP+ Silver", 30000],
  ["VVIP Gold", 75000],
  ["Royal Member Platinum", 150000],
  ["Black Card / Onyx Diamond", 300000],
  ["RUBYNOVA Ultimate Apex", 500000]
];

function audit(actor, action, reference = "", details = {}) {
  db.run("INSERT INTO audit(actor,action,reference,details) VALUES(?,?,?,?)",
    [actor || null, action, reference, JSON.stringify(details)]
  );
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: { error: "Terlalu banyak percobaan. Coba lagi nanti." }
});

app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100 }));

app.use(session({
  name: "rubynova.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7200000
  }
}));

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Silakan login." });
  next();
}

function adminOnly(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Akses admin ditolak." });
  }
  next();
}

function csrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const token = req.get("x-csrf-token");
  const expected = req.session ? req.session.csrf : null;

  if (!token || !expected) {
    return res.status(403).json({ error: "Token CSRF tidak valid." });
  }

  const tokenBuf = Buffer.from(token);
  const expectedBuf = Buffer.from(expected);

  if (tokenBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
    return res.status(403).json({ error: "Token CSRF tidak valid." });
  }
  next();
}
app.use("/api", csrf);

app.get("/api/csrf", (req, res) => {
  if (!req.session.csrf) {
    req.session.csrf = crypto.randomBytes(32).toString("hex");
  }
  res.json({ token: req.session.csrf });
});

app.post("/api/register", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10 || password.length > 128) {
    return res.status(400).json({ error: "Email atau kata sandi tidak valid (minimal 10 karakter)." });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    db.run("INSERT INTO users(email,password_hash) VALUES(?,?)", [email, hash], function(err) {
      if (err) return res.status(400).json({ error: "Email sudah terdaftar." });
      audit(this.lastID, "register");
      res.status(201).json({ message: "Akun berhasil dibuat." });
    });
  } catch {
    res.status(400).json({ error: "Gagal mendaftarkan akun." });
  }
});

app.post("/api/login", authLimiter, (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  db.get("SELECT * FROM users WHERE email=?", [email], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Email atau kata sandi salah." });
    }
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Sesi gagal dibuat." });
      req.session.user = { id: user.id, email: user.email, role: user.role };
      req.session.csrf = crypto.randomBytes(32).toString("hex");
      audit(user.id, "login");
      res.json({ user: req.session.user, csrfToken: req.session.csrf });
    });
  });
});

app.post("/api/logout", auth, (req, res) => {
  audit(req.session.user.id, "logout");
  req.session.destroy(() => res.json({ message: "Logout berhasil." }));
});

app.get("/api/me", auth, (req, res) => {
  db.get("SELECT id,email,role,coins FROM users WHERE id=?", [req.session.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: "Pengguna tidak ditemukan." });
    db.get(
      "SELECT tier,expires_at FROM vip WHERE user_id=? AND expires_at>CURRENT_TIMESTAMP ORDER BY expires_at DESC LIMIT 1",
      [user.id],
      (err, membership) => {
        res.json({ user, membership: membership || null });
      }
    );
  });
});

app.get("/api/products", (req, res) => {
  db.all("SELECT id,name,description,price FROM products WHERE active=1", [], (err, rows) => {
    res.json(rows || []);
  });
});

app.get("/api/vip/tiers", (req, res) => {
  res.json(tiers.map(([name, coins], index) => ({ index, name, coins, depositEquivalent: coins * 40 })));
});

app.post("/api/deposits", auth, (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isSafeInteger(amount) || amount < 20000 || amount > 20000000 || amount % 20000 !== 0) {
    return res.status(400).json({ error: "Nominal deposit harus kelipatan Rp20.000 (antara Rp20.000–Rp20.000.000)." });
  }
  const id = crypto.randomUUID();
  const reference = "RN-" + crypto.randomBytes(8).toString("hex").toUpperCase();
  const coins = Math.floor((amount / 20000) * 500);

  db.run(
    "INSERT INTO deposits(id,user_id,amount,coins,reference) VALUES(?,?,?,?,?)",
    [id, req.session.user.id, amount, coins, reference],
    (err) => {
      if (err) return res.status(500).json({ error: "Gagal membuat deposit." });
      audit(req.session.user.id, "deposit.created", id, { amount, coins });
      res.status(201).json({
        id, reference, amount, coins, status: "pending",
        message: "Belum dikreditkan. Tunggu admin memverifikasi pembayaran QRIS."
      });
    }
  );
});

app.get("/api/deposits", auth, (req, res) => {
  db.all(
    "SELECT id,amount,coins,reference,status,created_at FROM deposits WHERE user_id=? ORDER BY created_at DESC",
    [req.session.user.id],
    (err, rows) => res.json(rows || [])
  );
});

app.get("*", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RubyNova — Digital Marketplace</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#100c10;color:#f9f0f2;font:16px system-ui,-apple-system,sans-serif}
header{padding:22px;background:#1c1118;border-bottom:1px solid #522131}
h1{color:#ff5477;margin:0;font-size:24px}main{max-width:950px;margin:auto;padding:20px}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
button{background:#a91f49;color:white;border:0;padding:11px 15px;border-radius:9px;cursor:pointer;font-weight:600}
button:hover{background:#c8295b}
input{padding:12px;border-radius:8px;border:1px solid #66404d;background:#20161d;color:white;width:100%;margin:6px 0}
.card{background:#20161d;border:1px solid #492736;border-radius:14px;padding:16px;margin:12px 0}
small,.muted{color:#c7aab5}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#150d13;padding:12px;border-radius:8px;border:1px solid #361a25}
</style></head><body><header><h1>◆ RubyNova</h1>
<p style="margin:4px 0 0 0;color:#c7aab5">Digital Marketplace · VIP Membership</p></header><main>
<nav>
<button onclick="show('home')">Beranda</button>
<button onclick="show('login')">Login</button>
<button onclick="show('register')">Daftar</button>
<button onclick="show('wallet')">Saldo & Deposit</button>
<button onclick="show('vip')">VIP</button>
</nav><section id="content" class="card">Memuat RubyNova…</section>
<script>
let csrf="";
async function api(url,method="GET",body){
 const opt={method,headers:{}};
 if(body!==undefined){opt.headers["Content-Type"]="application/json";opt.headers["x-csrf-token"]=csrf;opt.body=JSON.stringify(body);}
 const r=await fetch("/api"+url,opt);const data=await r.json();
 if(data.csrfToken)csrf=data.csrfToken;
 if(!r.ok)throw Error(data.error||"Permintaan gagal");
 return data;
}
async function call(url,method,body){
 try{const d=await api(url,method,body);document.getElementById("result").textContent=JSON.stringify(d,null,2);}
 catch(e){document.getElementById("result").textContent=e.message;}
}
function form(title,fields,button,action){
 return '<h2>'+title+'</h2>'+fields.map(f=>'<input id="'+f[0]+'" placeholder="'+f[1]+'" '+(f[2]||"")+'/>').join("")+
 '<button onclick="'+action+'">'+button+'</button><pre id="result"></pre>';
}
async function show(page){
 const c=document.getElementById("content");
 if(page==="home")c.innerHTML='<h2>Selamat datang di RubyNova</h2><p>Toko produk digital, saldo koin, dan keanggotaan VIP.</p>';
 if(page==="register")c.innerHTML=form("Buat akun",[["email","Email","type=email"],["password","Kata sandi","type=password"]],"Daftar",'call("/register","POST",{email:email.value,password:password.value})');
 if(page==="login")c.innerHTML=form("Login",[["email","Email","type=email"],["password","Kata sandi","type=password"]],"Login",'call("/login","POST",{email:email.value,password:password.value})');
 if(page==="wallet")c.innerHTML=form("Ajukan deposit",[["amount","Nominal rupiah","type=number"]],"Ajukan",'call("/deposits","POST",{amount:Number(amount.value)})');
 if(page==="vip"){
  try{const d=await api("/vip/tiers");c.innerHTML="<h2>Enam Tingkat VIP</h2>"+d.map(t=>'<div class=card><b>'+t.name+'</b><p>'+t.coins.toLocaleString()+' koin</p></div>').join("");}
  catch(e){c.textContent=e.message}
 }
}
(async()=>{try{const d=await fetch("/api/csrf").then(r=>r.json());csrf=d.token;}catch{}show("home")})();
</script></main></body></html>`);
});

app.listen(PORT, () => console.log(`RubyNova aktif di port ${PORT}`));
