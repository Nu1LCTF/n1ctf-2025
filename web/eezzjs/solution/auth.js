const crypto = require('crypto');
const sha = require('sha.js');

const sha256 = (...messages) => {
    const hash = sha('sha256');
    messages.forEach((m) => hash.update(m));
    return hash.digest('hex');
};

const JWT_SECRET = crypto.randomBytes(9).toString('hex');

const toBase64Url = (input) => {
    const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
    return buffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
};

const fromBase64Url = (input) => {
    const paddedLength = (4 - (input.length % 4)) % 4;
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(paddedLength);
    return Buffer.from(base64, 'base64');
};

const hashPassword = (password, salt = '') => sha256(password, salt);

const signJWT = (payload, { expiresIn } = {}, secret = JWT_SECRET) => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    console.log(payload)
    const body = { ...payload,iat: now };
    if (expiresIn) {
        body.exp = now + expiresIn;
    }

    return [
        toBase64Url(JSON.stringify(header)),
        toBase64Url(JSON.stringify(body)),
        sha256(...[JSON.stringify(header), body, secret])
    ].join('.');
};

const verifyJWT = (token, secret = JWT_SECRET) => {
    if (typeof token !== 'string') {
        return null;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        return null;
    }

    const [encodedHeader, encodedPayload, signature] = parts;

    let header;
    let payload;
    try {
        header = JSON.parse(fromBase64Url(encodedHeader).toString());
        payload = JSON.parse(fromBase64Url(encodedPayload).toString());
    } catch (err) {
        return null;
    }

    const expectedSignatureHex = sha256(...[JSON.stringify(header), payload, secret]);

    let providedSignature;
    let expectedSignature;
    try {
        providedSignature = Buffer.from(signature, 'hex');
        expectedSignature = Buffer.from(expectedSignatureHex, 'hex');
    } catch (err) {
        return null;
    }

    if (
        providedSignature.length !== expectedSignature.length ||
        !crypto.timingSafeEqual(providedSignature, expectedSignature)
    ) {
        return null;
    }

    if (header.alg !== 'HS256') {
        return null;
    }

    if (payload.exp && Math.floor(Date.now() / 1000) >= payload.exp) {
        return null;
    }

    return payload;
};

module.exports = {
    hashPassword,
    signJWT,
    verifyJWT,
};
