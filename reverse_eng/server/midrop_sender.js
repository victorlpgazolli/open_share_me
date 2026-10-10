// Sender Mi Drop: conecta no Wi-Fi do receiver, faz o handshake DH e conversa em DES/ECB.
// Uso: node midrop_sender.js <SSID> <SENHA> <IP_DO_RECEIVER> [PORTA]
const net = require('net');
const os = require('os');
const { execFile } = require('child_process');
const {
    generateKeyPair, parseSpki, computeSharedSecret,
    encryptPacket, decryptPacket
} = require('./midrop_crypto');

const args = process.argv.slice(2);

if (args.length < 3) {
    console.log('Uso: node midrop_sender.js <SSID> <SENHA> <IP_DO_RECEIVER> [PORTA]');
    process.exit(1);
}

const [ssid, password, targetIp] = args;
const targetPort = args[3] ? parseInt(args[3], 10) : 8181;
const EOL = '\n'; // os celulares reais terminam cada linha só com \n

// Grupo DH padrão (o do celular antigo). O receiver adota o p/g que enviamos.
const keys = generateKeyPair();
let sharedSecret = null;
let pending = '';

// ==========================================
// Wi-Fi
// ==========================================
// execFile com array de argumentos: SSID/senha não passam por um shell,
// então aspas ou caracteres especiais não quebram nem injetam comandos.

function connectToWifi(ssid, password) {
    return new Promise((resolve, reject) => {
        const platform = os.platform();
        let cmd, cmdArgs;

        console.log(`\n[~] Conectando ao Wi-Fi: "${ssid}"...`);

        if (platform === 'linux') {
            cmd = 'nmcli';
            cmdArgs = ['dev', 'wifi', 'connect', ssid, 'password', password];
        } else if (platform === 'darwin') {
            cmd = 'networksetup';
            cmdArgs = ['-setairportnetwork', 'en1', ssid, password];
        } else if (platform === 'win32') {
            // No Windows o perfil da rede precisa já existir.
            cmd = 'netsh';
            cmdArgs = ['wlan', 'connect', `name=${ssid}`];
        } else {
            return reject(new Error('SO não suportado para Wi-Fi.'));
        }

        execFile(cmd, cmdArgs, (error) => {
            if (error) {
                console.error(`[-] Falha de Wi-Fi: ${error.message}`);
                return reject(error);
            }
            console.log('[+] Aguardando 5s para o DHCP...');
            setTimeout(resolve, 5000);
        });
    });
}

// ==========================================
// TCP
// ==========================================

function startTcpClient() {
    console.log(`\n[~] Conectando ao receiver TCP em ${targetIp}:${targetPort}...`);

    const client = new net.Socket();
    client.setKeepAlive(true, 5000);
    client.setEncoding('utf8');

    function sendEncrypted(obj) {
        client.write(encryptPacket(sharedSecret, JSON.stringify(obj)) + EOL);
    }

    // ---- JSON em texto puro (handshake) ----
    function handleControl(parsed) {
        console.log('[<] CONTROLE:', JSON.stringify(parsed));

        const iq = parsed.iq;
        if (!iq || iq.action !== 'send_pk_ack') {
            console.log('[?] JSON de controle não tratado.');
            return;
        }

        if (!iq.param) {
            console.error('[-] O receiver recusou nossa chave (param ausente).');
            return;
        }

        try {
            const receiverPk = JSON.parse(decodeURIComponent(iq.param)).pk;
            if (typeof receiverPk !== 'string' || !receiverPk) {
                throw new Error('send_pk_ack sem chave pública pk válida');
            }

            const { y, p, g } = parseSpki(receiverPk);
            if (p !== keys.group.p || g !== keys.group.g) {
                throw new Error('o receiver respondeu em outro grupo DH (p/g diferentes dos que enviamos)');
            }

            sharedSecret = computeSharedSecret(y, keys.x, keys.group);

            console.log('[+] Troca DH concluída.');
            console.log(`[+] Shared Secret: ${sharedSecret.toString('hex').slice(0, 16)}...`);
        } catch (err) {
            sharedSecret = null;
            console.error(`[-] Falha ao cruzar as chaves: ${err.message}`);
        }
    }

    // ---- Pacotes criptografados (base64, DES/ECB) ----
    function handleEncrypted(line) {
        if (!sharedSecret) {
            console.log('[!] Pacote criptografado antes do handshake; ignorado.');
            return;
        }

        let text;
        try {
            text = decryptPacket(sharedSecret, line);
        } catch (e) {
            console.error(`[-] Falha ao decifrar: ${e.message}`);
            return;
        }

        console.log(`[<] ${text}`);

        let msg;
        try { msg = JSON.parse(text); }
        catch { console.log('[?] Conteúdo decifrado não é JSON.'); return; }

        if (msg.ping) {
            // Formato do pong é um palpite; confirme contra o app real.
            sendEncrypted({ pong: { type: 'pong', id: msg.ping.id } });
            console.log(`[>] pong id=${msg.ping.id}`);
        } else {
            console.log('[?] Mensagem não tratada:');
            console.dir(msg, { depth: null, colors: true });
        }
    }

    client.connect(targetPort, targetIp, () => {
        console.log("[+] Conectado! Enviando 'send_pk'...");

        const payload = {
            iq: {
                type: 'set',
                xmlns: 'http://www.xiaomi.com/midrop',
                action: 'send_pk',
                param: encodeURIComponent(JSON.stringify({ pk: keys.publicKeyBase64 })),
                from: 'Redmi Note 8 Pro',
                profile: 0,
                versionCode: 34805
            }
        };

        client.write(JSON.stringify(payload) + EOL);
    });

    // TCP é um fluxo: acumula e processa só linhas completas.
    client.on('data', (data) => {
        pending += data;
        const lines = pending.split(/[\r\n\0]+/);
        pending = lines.pop(); // resto incompleto

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

    client.on('close', () => console.log('\n[-] Conexão encerrada.'));
    client.on('error', (err) => console.error(`\n[-] Erro: ${err.message}`));
}

// ==========================================
// START
// ==========================================

connectToWifi(ssid, password)
    .then(startTcpClient)
    .catch((err) => console.error(`[-] Wi-Fi falhou: ${err.message}`));