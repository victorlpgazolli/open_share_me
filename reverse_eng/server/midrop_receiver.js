// Receiver Mi Drop: aceita o send_pk, faz o DH no grupo (p, g) do sender e conversa em DES/ECB.
// Uso: node midrop_receiver.js [PORTA] [--no-ping]
// Variável: DOWNLOAD_DIR (padrão ./downloads)
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
    generateKeyPair, parseSpki, computeSharedSecret,
    encryptPacket, decryptPacket
} = require('./midrop_crypto');

const args = process.argv.slice(2);
const PORT = parseInt(args.find(a => /^\d+$/.test(a)) || '8181', 10);
const SEND_PINGS = !args.includes('--no-ping');
const PING_INTERVAL_MS = 3000;
const HOST = '0.0.0.0';
const EOL = '\n'; // os celulares reais terminam cada linha só com \n
const DOWNLOAD_DIR = process.env.DOWNLOAD_DIR || './downloads';

// ==========================================
// send_files2 + download HTTP
// ==========================================

// O `param` dos iq é um JSON com URL-encode.
function parseIqParam(iq) {
    if (!iq || typeof iq.param !== 'string') return null;
    try { return JSON.parse(decodeURIComponent(iq.param)); } catch { return null; }
}

// O nome vem do sender: nunca confiar nele como caminho.
function safeFileName(name) {
    const base = path.basename(String(name || 'arquivo'))
        .replace(/[\x00-\x1f<>:"/\\|?*]/g, '_')
        .replace(/^\.+/, '_');
    return base || 'arquivo';
}

function uniquePath(dir, name) {
    const ext = path.extname(name);
    const stem = path.basename(name, ext);
    let candidate = path.join(dir, name);
    for (let i = 1; fs.existsSync(candidate); i++) candidate = path.join(dir, `${stem} (${i})${ext}`);
    return candidate;
}

// uri vem como ":PORTA/caminho" (sem host: o host é o IP do sender) ou como URL completa.
// URL completa só é aceita se apontar para o próprio sender.
function buildFileUrl(peerIp, uri) {
    if (/^https?:\/\//i.test(uri)) {
        if (new URL(uri).hostname !== peerIp) throw new Error(`uri aponta para outro host: ${uri}`);
        return uri;
    }
    const m = /^:(\d+)(\/.*)?$/.exec(String(uri));
    if (!m) throw new Error(`formato de uri desconhecido: ${uri}`);
    return `http://${peerIp}:${m[1]}${m[2] || '/'}`;
}

// Cliente HTTP/1.0 mínimo sobre TCP. O servidor do celular manda Content-Length
// duplicado, e o parser do Node recusa isso (mesmo com insecureHTTPParser).
// A integridade é conferida depois pelo tamanho e pelo md5 da lista.
function downloadFile(url, entry) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        fs.mkdirSync(DOWNLOAD_DIR, { recursive: true });

        const sock = net.connect(Number(u.port) || 80, u.hostname);
        sock.setTimeout(15000, () => sock.destroy(new Error('timeout')));

        let head = Buffer.alloc(0);
        let headDone = false;
        let status = 0;
        let expected = null;            // Content-Length, quando existe
        let received = 0;
        let errBody = Buffer.alloc(0);  // corpo de respostas != 200, só para diagnóstico
        let out = null, hash = null, dest = null;
        let settled = false;

        const fail = (e) => {
            if (settled) return;
            settled = true;
            sock.destroy();
            if (out) out.destroy();
            if (dest) { try { fs.unlinkSync(dest); } catch { /* já removido */ } }
            reject(e);
        };

        const finish = () => {
            if (settled) return;
            if (!headDone) return fail(new Error('conexão fechada antes da resposta HTTP'));
            if (status !== 200) {
                return fail(new Error(`HTTP ${status}; corpo: ${errBody.toString('utf8').slice(0, 300)}`));
            }
            if (expected !== null && received < expected) {
                return fail(new Error(`conexão fechada com ${received} de ${expected} bytes`));
            }
            settled = true;
            sock.destroy();
            out.end(() => resolve({ dest, size: received, md5: hash.digest('hex') }));
        };

        const onBody = (buf) => {
            if (status !== 200) {
                if (errBody.length < 300) errBody = Buffer.concat([errBody, buf]);
                return;
            }
            if (expected !== null && received + buf.length > expected) {
                buf = buf.slice(0, expected - received);
            }
            hash.update(buf);
            out.write(buf);
            received += buf.length;
            if (expected !== null && received >= expected) finish();
        };

        sock.on('connect', () => {
            sock.write(`GET ${u.pathname}${u.search} HTTP/1.0\r\nHost: ${u.host}\r\nConnection: close\r\n\r\n`);
        });

        sock.on('data', (chunk) => {
            if (headDone) return onBody(chunk);

            head = Buffer.concat([head, chunk]);
            const end = head.indexOf('\r\n\r\n');
            if (end === -1) {
                if (head.length > 16384) fail(new Error('cabeçalho HTTP grande demais'));
                return;
            }

            const lines = head.slice(0, end).toString('latin1').split('\r\n');
            const rest = head.slice(end + 4);

            const m = /^HTTP\/\d\.\d (\d{3})\s*(.*)$/.exec(lines[0]);
            if (!m) return fail(new Error(`resposta HTTP inválida: ${lines[0]}`));
            status = Number(m[1]);

            const headers = {};         // nome -> lista de valores (aceita repetidos)
            for (const line of lines.slice(1)) {
                const i = line.indexOf(':');
                if (i < 1) continue;
                const k = line.slice(0, i).trim().toLowerCase();
                (headers[k] = headers[k] || []).push(line.slice(i + 1).trim());
            }
            console.log(`[~] HTTP ${status} ${m[2]}`);
            console.log(`[~] cabeçalhos: ${JSON.stringify(headers)}`);

            const lens = [...new Set(headers['content-length'] || [])];
            if (lens.length > 1) return fail(new Error(`Content-Length conflitante: ${lens.join(' vs ')}`));
            if (lens.length === 1) expected = Number(lens[0]);
            if ((headers['transfer-encoding'] || []).some((v) => /chunked/i.test(v))) {
                return fail(new Error('Transfer-Encoding chunked ainda não é suportado'));
            }

            headDone = true;
            if (status === 200) {
                dest = uniquePath(DOWNLOAD_DIR, safeFileName(entry.name));
                out = fs.createWriteStream(dest);
                hash = crypto.createHash('md5');
                out.on('error', fail);
                if (expected === 0) return finish();
            }
            if (rest.length) onBody(rest);
        });

        sock.on('close', finish);
        sock.on('error', fail);
    });
}

async function handleSendFiles(iq, peerIp) {
    const param = parseIqParam(iq);
    const list = param && Array.isArray(param.list) ? param.list : null;
    if (!list) {
        console.log('[?] send_files2 sem lista de arquivos.');
        return;
    }

    console.log(`[+] send_files2 id=${iq.id}: ${list.length} item(ns)`);
    for (const f of list) {
        console.log(`    - ${f.type} "${f.name}" ${f.sze} bytes md5=${f.md5} uri=${f.uri}`);
        if (f.is_dir) {
            console.log('      (diretório; ignorado por enquanto)');
            continue;
        }

        try {
            const url = buildFileUrl(peerIp, f.uri);
            console.log(`[~] Baixando ${url} ...`);
            const r = await downloadFile(url, f);

            const sizeOk = f.sze === undefined || r.size === Number(f.sze);
            const md5Ok = !f.md5 || r.md5 === String(f.md5).toLowerCase();
            console.log(`[${sizeOk && md5Ok ? '+' : '!'}] Salvo em ${r.dest} (${r.size} bytes, md5 ${r.md5})`);
            console.log(`    tamanho: ${sizeOk ? 'ok' : `DIFERENTE (esperado ${f.sze})`} | ` +
                        `md5: ${md5Ok ? 'ok' : `DIFERENTE (esperado ${f.md5})`}`);
        } catch (e) {
            console.error(`[-] Download falhou: ${e.message}`);
        }
    }
}

const server = net.createServer((socket) => {
    const tag = `${socket.remoteAddress}:${socket.remotePort}`;
    const peerIp = (socket.remoteAddress || '').replace(/^::ffff:/, '');
    console.log(`[+] Cliente conectado: ${tag}`);
    socket.setKeepAlive(true, 5000);
    socket.setEncoding('utf8');

    // Estado por conexão. As chaves só existem depois do send_pk,
    // porque o grupo DH (p, g) vem do sender.
    const state = {
        keys: null,
        secret: null,
        pingId: 0,
        pingTimer: null,
        pending: ''
    };

    function sendJson(obj) {
        socket.write(JSON.stringify(obj) + EOL);
    }

    function sendEncrypted(obj) {
        socket.write(encryptPacket(state.secret, JSON.stringify(obj)) + EOL);
    }

    function startPings() {
        if (!SEND_PINGS || state.pingTimer) return;
        const tick = () => {
            sendEncrypted({ ping: { type: 'ping', id: String(state.pingId) } });
            console.log(`[>] ping id=${state.pingId}`);
            state.pingId++;
        };
        tick();
        state.pingTimer = setInterval(tick, PING_INTERVAL_MS);
    }

    // ---- JSON em texto puro (handshake) ----
    function handleControl(parsed) {
        console.log('[<] CONTROLE:', JSON.stringify(parsed));

        const iq = parsed.iq;
        if (iq && iq.action === 'send_pk') {
            try {
                const senderPk = JSON.parse(decodeURIComponent(iq.param)).pk;
                const { y, p, g, format } = parseSpki(senderPk);
                const group = { p, g };

                console.log(`[~] Chave do sender: ${format}, grupo de ${p.toString(2).length} bits, ` +
                            `p=${p.toString(16).slice(0, 16)}...`);

                // Responde no MESMO grupo do sender.
                state.keys = generateKeyPair(group);
                state.secret = computeSharedSecret(y, state.keys.x, group);
            } catch (e) {
                console.error(`[-] send_pk inválido: ${e.message}`);
                // Sem param no ack = recusa
                sendJson({ iq: { type: 'set', xmlns: 'http://www.xiaomi.com/midrop',
                                 action: 'send_pk_ack', profile: 1,
                                 versionCode: iq.versionCode || 34805 } });
                return;
            }

            sendJson({
                iq: {
                    type: 'set',
                    xmlns: 'http://www.xiaomi.com/midrop',
                    action: 'send_pk_ack',
                    param: encodeURIComponent(JSON.stringify({ pk: state.keys.publicKeyBase64 })),
                    profile: 1,
                    versionCode: iq.versionCode || 34805
                }
            });
            console.log(`[>] send_pk_ack enviado. Segredo: ${state.secret.toString('hex').slice(0, 16)}...`);
            console.log(`[+] Canal criptografado pronto (de: ${iq.from || '?'})`);
            startPings();
            return;
        }

        console.log('[?] JSON de controle não tratado.');
    }

    // ---- Pacotes criptografados (base64, DES/ECB) ----
    function handleEncrypted(line) {
        if (!state.secret) {
            console.log('[!] Pacote criptografado antes do handshake; ignorado.');
            return;
        }

        let text;
        try {
            text = decryptPacket(state.secret, line);
        } catch (e) {
            console.error(`[-] Falha ao decifrar: ${e.message}`);
            return;
        }

        console.log(`[<] ${text}`);

        let msg;
        try { msg = JSON.parse(text); }
        catch { console.log('[?] Conteúdo decifrado não é JSON.'); return; }

        if (msg.ping) {
            // Formato do pong é um palpite; confirme com o app real.
            sendEncrypted({ pong: { type: 'pong', id: msg.ping.id } });
            console.log(`[>] pong id=${msg.ping.id}`);
        } else if (msg.pong) {
            console.log(`[~] pong recebido id=${msg.pong.id}`);
        } else if (msg.iq && msg.iq.action === 'send_files2') {
            handleSendFiles(msg.iq, peerIp).catch((e) => console.error(`[-] send_files2: ${e.message}`));
        } else {
            console.log('[?] Mensagem não tratada:');
            console.log(JSON.stringify(msg, null, 2));
            const decoded = parseIqParam(msg.iq);
            if (decoded) {
                console.log('    param decodificado:');
                console.log(JSON.stringify(decoded, null, 2));
            }
        }
    }

    // TCP é um fluxo: acumula e processa só linhas completas.
    socket.on('data', (data) => {
        state.pending += data;
        const lines = state.pending.split(/[\r\n\0]+/);
        state.pending = lines.pop(); // resto incompleto

        for (const raw of lines) {
            const line = raw.trim();
            if (!line) continue;

            if (line.startsWith('{')) {
                try { handleControl(JSON.parse(line)); }
                catch (e) { console.error(`[-] JSON inválido: ${e.message}`); }
            } else {
                handleEncrypted(line);
            }
        }
    });

    const cleanup = () => { if (state.pingTimer) clearInterval(state.pingTimer); };

    socket.on('end', () => console.log(`[-] Cliente desconectou: ${tag}`));
    socket.on('close', cleanup);
    socket.on('error', (err) => {
        cleanup();
        if (err.code === 'ECONNRESET') console.log(`[-] Conexão resetada: ${tag}`);
        else console.error(`[-] Erro no socket: ${err.message}`);
    });
});

server.listen(PORT, HOST, () => {
    console.log(`Receiver rodando em TCP na porta ${PORT} (pings: ${SEND_PINGS ? 'on' : 'off'})`);
    console.log('Aguardando conexões...');
});