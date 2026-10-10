// Cripto compartilhada do protocolo Mi Drop: DH (BigInt) + DER + DES/ECB.
//
// O grupo DH (p, g) NÃO é fixo. Celulares antigos usam sempre o mesmo grupo, mas
// os novos (ex.: Redmi Note 14 5G) mandam um p/g/q diferente a cada sessão, num
// SPKI X9.42 (OID 1.2.840.10046.2.1). Quem responde usa o mesmo p/g do remetente
// (SPKI PKCS#3, OID 1.2.840.113549.1.3.1) e calcula o segredo módulo esse p.
const crypto = require('crypto');

// Grupo dos celulares antigos; também é o que o sender usa por padrão.
const DEFAULT_GROUP = {
    p: BigInt('0xad2da572b49028ecd6e5ac40eeaf0d0a834805ba11e0aaee1357f8177a2190a3'),
    g: BigInt('0x5c6a17022bddf71c64b656da3896a97753af89782888653e6491031f19e46b70')
};

const MIN_P_BITS = 64;
const MAX_P_BITS = 4096;

const OID_PKCS3 = '2a864886f70d010301';   // dhKeyAgreement
const OID_X942 = '2a8648ce3e0201';        // dhpublicnumber

function modPow(base, exp, mod) {
    let res = 1n;
    base %= mod;
    while (exp > 0n) {
        if (exp & 1n) res = (res * base) % mod;
        exp >>= 1n;
        base = (base * base) % mod;
    }
    return res;
}

function bitLength(bi) { return bi.toString(2).length; }
function byteLength(bi) { return Math.ceil(bitLength(bi) / 8); }

function bigToBuf(bi, size) {
    let hex = bi.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    if (size) {
        if (hex.length > size * 2) throw new Error('BigInt maior que o tamanho esperado');
        hex = hex.padStart(size * 2, '0');
    }
    return Buffer.from(hex, 'hex');
}

function bufToBig(buf) {
    if (!buf.length) throw new Error('INTEGER vazio');
    return BigInt('0x' + buf.toString('hex'));
}

function checkGroup({ p, g }) {
    const bits = bitLength(p);
    if (bits < MIN_P_BITS || bits > MAX_P_BITS) throw new Error(`p com ${bits} bits fora do esperado`);
    if (!(p & 1n)) throw new Error('p é par');
    if (g <= 1n || g >= p - 1n) throw new Error('g fora do intervalo');
}

// ---------- DER ----------
function derLen(n) {
    if (n < 0x80) return Buffer.from([n]);
    const bytes = [];
    while (n > 0) { bytes.unshift(n & 0xff); n >>>= 8; }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, value) {
    return Buffer.concat([Buffer.from([tag]), derLen(value.length), value]);
}

function derInt(buf) {
    let b = Buffer.from(buf);
    while (b.length > 1 && b[0] === 0) b = b.slice(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return tlv(0x02, b);
}

function readTlv(buf, off = 0) {
    if (off + 2 > buf.length) throw new Error('DER: dados truncados');
    const tag = buf[off++];
    let len = buf[off++];
    if (len & 0x80) {
        const n = len & 0x7f;
        if (n === 0 || n > 4 || off + n > buf.length) throw new Error('DER: comprimento inválido');
        len = 0;
        for (let i = 0; i < n; i++) len = len * 256 + buf[off++];
    }
    const end = off + len;
    if (end > buf.length) throw new Error('DER: TLV ultrapassa o buffer');
    return { tag, value: buf.slice(off, end), end };
}

// SubjectPublicKeyInfo no formato PKCS#3 (p, g), igual ao que o receiver Android devolve.
function buildSpki(y, group = DEFAULT_GROUP) {
    const params = tlv(0x30, Buffer.concat([derInt(bigToBuf(group.p)), derInt(bigToBuf(group.g))]));
    const alg = tlv(0x30, Buffer.concat([Buffer.from('06092a864886f70d010301', 'hex'), params]));
    const bits = tlv(0x03, Buffer.concat([Buffer.from([0]), derInt(bigToBuf(y))]));
    return tlv(0x30, Buffer.concat([alg, bits]));
}

// Lê um SPKI em base64 (PKCS#3 ou X9.42) e devolve { y, p, g, format }.
function parseSpki(base64) {
    const buf = Buffer.from(base64, 'base64');
    const outer = readTlv(buf);
    if (outer.tag !== 0x30) throw new Error('SPKI não começa com SEQUENCE');

    const alg = readTlv(outer.value, 0);
    if (alg.tag !== 0x30) throw new Error('AlgorithmIdentifier inválido');

    const bits = readTlv(outer.value, alg.end);
    if (bits.tag !== 0x03 || bits.value[0] !== 0) throw new Error('BIT STRING inválido');
    const yTlv = readTlv(bits.value.slice(1));
    if (yTlv.tag !== 0x02) throw new Error('Y não é INTEGER');

    // OID + parâmetros. PKCS#3: (p, g[, l]). X9.42: (p, g, q, j...). Só p e g interessam.
    const oid = readTlv(alg.value, 0);
    const params = readTlv(alg.value, oid.end);
    if (oid.tag !== 0x06 || params.tag !== 0x30) throw new Error('Parâmetros DH ausentes');
    const pTlv = readTlv(params.value, 0);
    const gTlv = readTlv(params.value, pTlv.end);
    if (pTlv.tag !== 0x02 || gTlv.tag !== 0x02) throw new Error('p/g não são INTEGER');

    const p = bufToBig(pTlv.value);
    const g = bufToBig(gTlv.value);
    const y = bufToBig(yTlv.value);
    checkGroup({ p, g });

    const oidHex = oid.value.toString('hex');
    const format = oidHex === OID_X942 ? 'X9.42' : oidHex === OID_PKCS3 ? 'PKCS#3' : `OID ${oidHex}`;
    return { y, p, g, format };
}

// ---------- DH ----------
// Par de chaves no grupo informado. x em [2, p-2].
function generateKeyPair(group = DEFAULT_GROUP) {
    checkGroup(group);
    const raw = BigInt('0x' + crypto.randomBytes(byteLength(group.p)).toString('hex'));
    const x = (raw % (group.p - 3n)) + 2n;
    const y = modPow(group.g, x, group.p);
    return { x, y, group, publicKeyBase64: buildSpki(y, group).toString('base64') };
}

// K = Y_peer ^ x mod p, com o tamanho de p e zeros à esquerda (como o Java faz).
function computeSharedSecret(peerY, x, group = DEFAULT_GROUP) {
    if (peerY <= 1n || peerY >= group.p - 1n) throw new Error('Y do peer fora do intervalo');
    const k = modPow(peerY, x, group.p);
    if (k === 0n) throw new Error('Segredo compartilhado zerado');
    return bigToBuf(k, byteLength(group.p));
}

// ---------- DES/ECB/PKCS5 (Java "DES") ----------
// Chave = 8 primeiros bytes do segredo. O Node/OpenSSL 3 não expõe DES simples
// sem o provider legacy, então usamos 3DES com K1=K2=K3, que é equivalente.
function desKey(secret) {
    const k = secret.slice(0, 8);
    return Buffer.concat([k, k, k]);
}

function decryptToBuffer(secret, base64) {
    const d = crypto.createDecipheriv('des-ede3-ecb', desKey(secret), null);
    return Buffer.concat([d.update(Buffer.from(base64, 'base64')), d.final()]);
}

function decryptPacket(secret, base64) {
    return decryptToBuffer(secret, base64).toString('utf8');
}

// Aceita string (utf8) ou Buffer (byte a byte, útil para o proxy).
function encryptPacket(secret, data) {
    const input = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    const c = crypto.createCipheriv('des-ede3-ecb', desKey(secret), null);
    return Buffer.concat([c.update(input), c.final()]).toString('base64');
}

module.exports = {
    DEFAULT_GROUP, modPow,
    generateKeyPair, parseSpki, buildSpki, computeSharedSecret,
    encryptPacket, decryptPacket, decryptToBuffer,
    _der: { tlv, derInt, bigToBuf }
};