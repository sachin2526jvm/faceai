const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

// =============================================
//  CONFIG — apni keys yahan hain
// =============================================
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const MONGODB_URI        = process.env.MONGODB_URI        || '';
const PORT               = process.env.PORT || 3000;
const SECRET             = 'faceai_secret_2024';
const ADMIN_USERNAME     = 'admin';
const ADMIN_PASSWORD     = 'admin123';

// =============================================
//  MongoDB
// =============================================
let db;

async function connectDB() {
  const client = new MongoClient(MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000,
    tls: true
  });
  await client.connect();
  db = client.db('faceai');
  console.log('  MongoDB connected!');
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('users').createIndex({ username: 1 }, { unique: true });
}

function col(name) { return db.collection(name); }
function hashPassword(p) { return crypto.createHmac('sha256', SECRET).update(p).digest('hex'); }

// =============================================
//  Sessions — simple in-memory
// =============================================
const sessions = {};

function createSession(user, isAdmin) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = {
    id: user.id,
    username: user.username,
    email: user.email,
    isAdmin: isAdmin || false
  };
  return token;
}

function getSession(token) {
  return token ? sessions[token] : null;
}

function destroySession(token) {
  if (token) delete sessions[token];
}

function getToken(cookieHeader) {
  if (!cookieHeader) return null;
  const m = cookieHeader.match(/session=([^;]+)/);
  return m ? m[1] : null;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function serveFile(res, filename) {
  const filePath = path.join(__dirname, 'public', filename);
  if (!fs.existsSync(filePath)) { res.writeHead(404); res.end('404 Not Found'); return; }
  const mimes = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript' };
  res.writeHead(200, { 'Content-Type': mimes[path.extname(filename)] || 'text/plain' });
  res.end(fs.readFileSync(filePath));
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// =============================================
//  HTTP Server
// =============================================
const server = http.createServer(async (req, res) => {
  const url    = req.url.split('?')[0];
  const method = req.method;
  const token  = getToken(req.headers.cookie);
  const session = getSession(token);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ---- REGISTER ----
  if (method === 'POST' && url === '/api/register') {
    const { username, email, password } = await parseBody(req);
    if (!username || !email || !password) return json(res, 400, { error: 'All fields are required.' });
    if (password.length < 6) return json(res, 400, { error: 'Password must be at least 6 characters.' });
    try {
      const newUser = {
        id: Date.now().toString(),
        username, email,
        password: hashPassword(password),
        status: 'active',
        createdAt: new Date()
      };
      await col('users').insertOne(newUser);
      const t = createSession({ id: newUser.id, username, email }, false);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'session=' + t + '; HttpOnly; Path=/; Max-Age=86400' });
      res.end(JSON.stringify({ success: true, username }));
    } catch (err) {
      if (err.code === 11000) {
        const field = err.message.includes('email') ? 'Email' : 'Username';
        return json(res, 409, { error: field + ' already taken.' });
      }
      return json(res, 500, { error: 'Registration failed: ' + err.message });
    }
    return;
  }

  // ---- LOGIN ----
  if (method === 'POST' && url === '/api/login') {
    const { email, password } = await parseBody(req);
    if (!email || !password) return json(res, 400, { error: 'Email and password are required.' });
    const user = await col('users').findOne({ email, password: hashPassword(password) });
    if (!user) return json(res, 401, { error: 'Invalid email or password.' });
    if (user.status === 'blocked') return json(res, 403, { error: 'Your account has been blocked.' });
    const t = createSession({ id: user.id, username: user.username, email: user.email }, false);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'session=' + t + '; HttpOnly; Path=/; Max-Age=86400' });
    res.end(JSON.stringify({ success: true, username: user.username }));
    return;
  }

  // ---- ADMIN LOGIN ----
  if (method === 'POST' && url === '/api/admin/login') {
    const { username, password } = await parseBody(req);
    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD)
      return json(res, 401, { error: 'Invalid admin credentials.' });
    const t = createSession({ id: 'admin', username: 'admin', email: 'admin@faceai.com' }, true);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'session=' + t + '; HttpOnly; Path=/; Max-Age=86400' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // ---- LOGOUT ----
  if (method === 'POST' && url === '/api/logout') {
    destroySession(token);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // ---- AUTH STATUS ----
  if (method === 'GET' && url === '/api/me') {
    if (!session) return json(res, 401, { loggedIn: false });
    return json(res, 200, { loggedIn: true, username: session.username, email: session.email, isAdmin: session.isAdmin });
  }

  // ---- MY ANALYSES ----
  if (method === 'GET' && url === '/api/my-analyses') {
    if (!session) return json(res, 401, { error: 'Please login.' });
    const analyses = await col('analyses').find({ userId: session.id }).sort({ createdAt: -1 }).toArray();
    return json(res, 200, analyses);
  }

  // ---- ADMIN: ALL USERS ----
  if (method === 'GET' && url === '/api/admin/users') {
    if (!session || !session.isAdmin) return json(res, 403, { error: 'Admin access required.' });
    const users = await col('users').find({}, { projection: { password: 0 } }).toArray();
    const result = await Promise.all(users.map(async function(u) {
      const total = await col('analyses').countDocuments({ userId: u.id });
      const last  = await col('analyses').findOne({ userId: u.id }, { sort: { createdAt: -1 } });
      return Object.assign({}, u, { totalAnalyses: total, lastAnalysis: last ? last.createdAt : null });
    }));
    return json(res, 200, result);
  }

  // ---- ADMIN: ALL ANALYSES ----
  if (method === 'GET' && url === '/api/admin/analyses') {
    if (!session || !session.isAdmin) return json(res, 403, { error: 'Admin access required.' });
    const analyses = await col('analyses').find({}).sort({ createdAt: -1 }).toArray();
    return json(res, 200, analyses);
  }

  // ---- ADMIN: BLOCK/UNBLOCK ----
  if (method === 'POST' && url === '/api/admin/toggle-block') {
    if (!session || !session.isAdmin) return json(res, 403, { error: 'Admin access required.' });
    const { userId } = await parseBody(req);
    const user = await col('users').findOne({ id: userId });
    if (!user) return json(res, 404, { error: 'User not found.' });
    const newStatus = user.status === 'blocked' ? 'active' : 'blocked';
    await col('users').updateOne({ id: userId }, { $set: { status: newStatus } });
    return json(res, 200, { success: true, status: newStatus });
  }

  // ---- ADMIN: DELETE USER ----
  if (method === 'POST' && url === '/api/admin/delete-user') {
    if (!session || !session.isAdmin) return json(res, 403, { error: 'Admin access required.' });
    const { userId } = await parseBody(req);
    await col('users').deleteOne({ id: userId });
    await col('analyses').deleteMany({ userId });
    return json(res, 200, { success: true });
  }

  // ---- FACE ANALYSIS ----
  if (method === 'POST' && url === '/api/analyze') {
    if (!session) return json(res, 401, { error: 'Session expired. Please login again.' });

    const { imageBase64, mimeType } = await parseBody(req);
    if (!imageBase64) return json(res, 400, { error: 'No image provided.' });

    if (imageBase64.length > 1400000) {
      return json(res, 400, { error: 'Image too large. Please use a smaller image (under 1MB).' });
    }

    // ── Free Vision Models — April 2026 mein available & accurate ───────────────
    // NOTE: gemini-2.0-flash-exp:free Feb 2026 mein deprecated ho gaya, use mat karo
    const FREE_MODELS = [
       'openrouter/free', 
      'meta-llama/llama-4-maverick:free',           // ★ BEST  — Llama 4 Maverick, 400B MoE, top vision
      'meta-llama/llama-4-scout:free',              // ★ GREAT — Llama 4 Scout, 109B MoE, fast + accurate
      'google/gemini-2.5-pro-exp-03-25:free',       // ★ GREAT — Gemini 2.5 Pro FREE (experimental)
      'moonshotai/kimi-vl-a3b-thinking:free',       // ★ GOOD  — Kimi VL thinking model, reasoning vision
      'qwen/qwen3.6-plus:free',                     // ★ GOOD  — Qwen 3.6 Plus, 1M context, vision
      'qwen/qwen2.5-vl-72b-instruct:free',          //   GOOD  — Qwen 2.5 VL 72B, strong vision
      'qwen/qwen2.5-vl-32b-instruct:free',          //   GOOD  — Qwen 2.5 VL 32B
      'mistralai/mistral-small-3.1-24b-instruct:free', // DECENT — Mistral Small 3.1
      'meta-llama/llama-3.2-11b-vision-instruct:free', // DECENT — Llama 3.2 Vision
      'google/gemma-3-27b-it:free',                 //   BASIC — Gemma 3 27B
      'google/gemma-3-12b-it:free',                 //   BASIC — Gemma 3 12B
      'google/gemma-3-4b-it:free',                  //   BASIC — last fallback
    ];

    const prompt = `You are an expert forensic facial analysis AI specializing in accurate age estimation. Analyze the face in this image and return a JSON object ONLY - no markdown, no backticks, no extra text.

CRITICAL AGE ESTIMATION RULES - follow these strictly:
- Carefully examine: facial bone structure, jawline development, cheek fat, skin smoothness, eye area
- Teenagers (13-17): rounded soft cheeks, undeveloped jawline, baby fat still present, very smooth skin
- Young adults (18-24): more defined jaw, slight cheekbone visibility, skin still very smooth
- Adults (25+): jawline sharp, cheekbones visible, slight skin texture, forehead lines may appear
- NEVER round up a teenage face to adult age. If it looks like a teenager, say teenager age.
- Give a NARROW 2-3 year range only. Example: "14-16" or "17-19" NOT "18-25"
- Be honest and accurate.

JSON structure:
{
  "detected": true,
  "confidence": "High|Medium|Low",
  "faces_count": 1,
  "cards": [
    {"label": "Estimated Age", "value": "14-16", "color": "accent"},
    {"label": "Gender", "value": "Male", "color": "accent2"},
    {"label": "Emotion", "value": "Happy", "color": "accent3"},
    {"label": "Attention", "value": "Direct", "color": "success"}
  ],
  "bars": [
    {"label": "Happiness", "value": 85},
    {"label": "Calmness", "value": 60},
    {"label": "Confidence", "value": 72},
    {"label": "Engagement", "value": 78}
  ],
  "tags": ["Smiling", "Eye contact", "Clear photo", "Frontal pose"],
  "summary": "3-4 sentences describing facial features, estimated age reasoning, expression, and notable characteristics."
}
If no face detected: set detected false, explain in summary.`;

    // ── Try each model one by one until success ───────────────────────────────
    async function tryModel(modelName) {
      const controller = new AbortController();
      const tid = setTimeout(function() { controller.abort(); }, 30000);
      try {
        const apiRes = await fetch('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST',
          signal: controller.signal,
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + OPENROUTER_API_KEY,
            'HTTP-Referer': 'http://localhost:' + PORT,
            'X-Title': 'FaceAI'
          },
          body: JSON.stringify({
            model: modelName,
            max_tokens: 1000,
            messages: [{
              role: 'user',
              content: [
                { type: 'image_url', image_url: { url: 'data:' + (mimeType || 'image/jpeg') + ';base64,' + imageBase64 } },
                { type: 'text', text: prompt }
              ]
            }]
          })
        });
        clearTimeout(tid);
        const data = await apiRes.json();
        if (data.error) {
          console.log('  [SKIP] ' + modelName + ' — ' + data.error.message);
          return null;
        }
        const text = (data.choices && data.choices[0]) ? data.choices[0].message.content : '';
        if (!text || text.length < 10) return null;
        const clean = text.replace(/```json|```/g, '').trim();
        let parsed;
        try { parsed = JSON.parse(clean); } catch(e) { return null; }
        console.log('  [OK]   ' + modelName);
        return { clean: clean, parsed: parsed };
      } catch (err) {
        clearTimeout(tid);
        console.log('  [FAIL] ' + modelName + ' — ' + err.message);
        return null;
      }
    }

    try {
      let finalResult = null;
      let usedModel   = null;

      for (var mi = 0; mi < FREE_MODELS.length; mi++) {
        console.log('  Trying: ' + FREE_MODELS[mi]);
        var attempt = await tryModel(FREE_MODELS[mi]);
        if (attempt) { finalResult = attempt; usedModel = FREE_MODELS[mi]; break; }
      }

      if (!finalResult) {
        return json(res, 502, { error: 'All free models are currently unavailable. Please try again in a moment.' });
      }

      const { clean, parsed } = finalResult;

      // Save to MongoDB
      await col('analyses').insertOne({
        id: Date.now().toString(),
        userId: session.id,
        username: session.username,
        model: usedModel,
        emotion:  parsed.cards ? (parsed.cards.find(function(c){ return c.label === 'Emotion'; }) || {}).value || 'N/A' : 'N/A',
        age:      parsed.cards ? (parsed.cards.find(function(c){ return c.label === 'Estimated Age'; }) || {}).value || 'N/A' : 'N/A',
        gender:   parsed.cards ? (parsed.cards.find(function(c){ return c.label === 'Gender'; }) || {}).value || 'N/A' : 'N/A',
        confidence: parsed.confidence || 'N/A',
        facesDetected: parsed.detected ? (parsed.faces_count || 1) : 0,
        summary: parsed.summary || '',
        createdAt: new Date()
      });

      return json(res, 200, { result: clean, model: usedModel });
    } catch (err) {
      return json(res, 500, { error: err.message });
    }
  }

  // ---- STATIC FILES ----
  if (method === 'GET') {
    if (url === '/' || url === '/index.html') return serveFile(res, 'index.html');
    if (url === '/login')       return serveFile(res, 'login.html');
    if (url === '/register')    return serveFile(res, 'register.html');
    if (url === '/about')       return serveFile(res, 'about.html');
    if (url === '/history')     return serveFile(res, 'history.html');
    if (url === '/camera')      return serveFile(res, 'camera.html');
    if (url === '/admin')       return serveFile(res, 'admin.html');
    if (url === '/admin-login') return serveFile(res, 'admin-login.html');
    const file = url.slice(1);
    if (fs.existsSync(path.join(__dirname, 'public', file))) return serveFile(res, file);
  }

  res.writeHead(404); res.end('404 Not Found');
});

// =============================================
//  Start
// =============================================
connectDB().then(function() {
  server.listen(PORT, function() {
    console.log('');
    console.log('  FaceAI is running!');
    console.log('  Open: http://localhost:' + PORT);
    console.log('  Admin: http://localhost:' + PORT + '/admin-login');
    console.log('');
  });
}).catch(function(err) {
  console.error('MongoDB connection failed:', err.message);
  process.exit(1);
});
