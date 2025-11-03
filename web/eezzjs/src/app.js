const express = require('express');
const ejs = require('ejs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.use(express.json({
    limit: '1mb'
}));
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const {
    hashPassword,
    signJWT,
    verifyJWT,
} = require('./auth');

const TOKEN_COOKIE_NAME = 'token';

const users = new Map();
const ADMIN_USERNAME = 'admin';
const adminPasswordPlain = crypto.randomBytes(9).toString('hex');
const adminPasswordHash = hashPassword(adminPasswordPlain, ADMIN_USERNAME);
users.set(ADMIN_USERNAME, { passwordHash: adminPasswordHash });

console.log(`[system] username: ${ADMIN_USERNAME}`);
console.log(`[system] password: ${adminPasswordPlain}`);

function getTokenFromCookies(req) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) {
        return null;
    }

    const cookies = cookieHeader.split(';').map((segment) => segment.trim());
    for (const cookie of cookies) {
        const [name, ...rest] = cookie.split('=');
        if (name === TOKEN_COOKIE_NAME) {
            return decodeURIComponent(rest.join('='));
        }
    }

    return null;
}

function authenticateJWT(req, res, next) {
    const token = getTokenFromCookies(req);

    if (!token) {
        return res.status(401).json({ error: 'No login credentials provided' });
    }

    const payload = verifyJWT(token);
    if (!payload) {
        return res.status(401).json({ error: 'Login credentials are invalid or expired' });
    }

    req.user = payload;
    next();
}

function serveIndex(req, res) {
    var templ = req.query.templ || 'index';
    var lsPath = path.join(__dirname, req.path);
    try {
        res.render(templ, {
            filenames: fs.readdirSync(lsPath),
            path: req.path
        });
    } catch (e) {
        console.log(e);
        res.status(500).send('Error rendering page');
    }
}

function renderLoginPage(req, res) {
    res.render('login');
}

function renderUploadPage(req, res) {
    const token = getTokenFromCookies(req);
    if (!token) {
        return res.redirect('/login');
    }

    const payload = verifyJWT(token);
    if (!payload) {
        return res.redirect('/login');
    }

    res.render('upload');
}

function loginUser(req, res) {
    const { username, password } = req.body || {};

    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username or password format is invalid' });
    }

    const trimmedUsername = username.trim();
    const userRecord = users.get(trimmedUsername);
    if (!userRecord) {
        return res.status(401).json({ error: 'Incorrect username or password' });
    }

    const passwordHash = hashPassword(password, trimmedUsername);
    if (passwordHash !== userRecord.passwordHash) {
        return res.status(401).json({ error: 'Incorrect username or password' });
    }

    const token = signJWT({ username: trimmedUsername }, { expiresIn: 3600 });
    res.cookie(TOKEN_COOKIE_NAME, token, {
        httpOnly: true,
        maxAge: 3600 * 1000,
    });
    return res.status(204).send();
}

function uploadFile(req, res) {
    var {filedata,filename}=req.body;
    var ext = path.extname(filename).toLowerCase();

    if (/js/i.test(ext)) {
        return  res.status(403).send('Denied filename');
    }
    var filepath = path.join(uploadDir,filename);

    if (fs.existsSync(filepath)) {
        return res.status(500).send('File already exists');
    }

    fs.writeFile(filepath, filedata, 'base64', (err) => {
        if (err) {
            console.log(err);
            res.status(500).send('Error saving file');
        } else {
            res.status(200).send({ message: 'File uploaded successfully', path: `/uploads/${path}` });
        }
    });
}

app.get('/', serveIndex);
app.get('/login', renderLoginPage);
app.get('/upload', renderUploadPage);
app.post('/login', loginUser);
app.post('/upload', authenticateJWT, uploadFile);
app.use('/uploads', express.static(uploadDir));


if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}
