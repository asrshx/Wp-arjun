const express = require("express");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const pino = require("pino");
const {
    makeWASocket,
    useMultiFileAuthState,
    delay,
    makeCacheableSignalKeyStore,
    Browsers,
    fetchLatestBaileysVersion,
    DisconnectReason
} = require("@whiskeysockets/baileys");
const { randomBytes, createHash } = require("crypto");
const qrcode = require("qrcode");

const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
if (majorVersion > 20) {
    console.warn(`Ã¢Å¡ Ã¯Â¸Â Node.js version ${nodeVersion} detected.`);
    console.warn(`Ã¢Å¡ Ã¯Â¸Â This application works best with Node.js 18 or 20 (LTS).`);
}

const app = express();
const PORT = process.env.PORT || 21592;

// Directories
const AUTH_DIR = "./auth_sessions";
const UPLOAD_DIR = "./uploads";
const TEMP_DIR = "./temp";
const PUBLIC_DIR = "./public";
[AUTH_DIR, UPLOAD_DIR, TEMP_DIR, PUBLIC_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

const upload = multer({ dest: UPLOAD_DIR });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));

// Data stores
const users = new Map();
const ADMIN_USER = "arjun";
const ADMIN_PASS_HASH = createHash("sha256").update("arjun").digest("hex");
const userSessions = new Map();
const userToSessions = new Map();
const activeTasks = new Map();
const sessionReinitializing = new Map();

function generateId(prefix = "") {
    return prefix + randomBytes(16).toString("hex");
}
function hashPassword(pwd) {
    return createHash("sha256").update(pwd).digest("hex");
}
function setUserCookie(res, username) {
    res.cookie("user", username, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
}
function setAdminCookie(res) {
    res.cookie("admin", "true", { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
}
function getUserFromCookie(req) {
    return req.cookies.user || null;
}
function isAdmin(req) {
    return req.cookies.admin === "true";
}

// ---------- Ã Â¤ÂªÃ Â¥â€šÃ Â¤Â°Ã Â¥â‚¬ Ã Â¤Â¤Ã Â¤Â°Ã Â¤Â¹ Ã Â¤Â¸Ã Â¥â€¡ Ã Â¤Â°Ã Â¥â‚¬Ã Â¤â€¡Ã Â¤Â¨Ã Â¤Â¿Ã Â¤Â¶Ã Â¤Â¿Ã Â¤Â¯Ã Â¤Â²Ã Â¤Â¾Ã Â¤â€¡Ã Â¤Å“Ã Â¤Â¼ (Bad MAC Ã Â¤â€¢Ã Â¥â€¡ Ã Â¤Â¬Ã Â¤Â¾Ã Â¤Â¦) ----------
async function reinitializeWhatsAppSession(sessionId) {
    if (sessionReinitializing.get(sessionId)) return;
    sessionReinitializing.set(sessionId, true);
    console.log(`Ã°Å¸â€â€ž Force reinitializing session ${sessionId} due to crypto error...`);
    
    const sess = userSessions.get(sessionId);
    if (!sess) {
        sessionReinitializing.delete(sessionId);
        return;
    }
    
    sess.isConnected = false;
    if (sess.client) {
        try { sess.client.end(); } catch(e) {}
        sess.client = null;
    }
    
    await initWhatsAppSession(sessionId, sess.userId, sess.number);
    
    let waited = 0;
    while (waited < 30) {
        const current = userSessions.get(sessionId);
        if (current && current.isConnected && current.client) break;
        await delay(1000);
        waited++;
    }
    
    sessionReinitializing.delete(sessionId);
    console.log(`Ã¢Å“â€¦ Session ${sessionId} reinitialization complete, connected: ${userSessions.get(sessionId)?.isConnected}`);
}

// ---------- PAIRING CODE ENDPOINT ----------
app.post("/generate-pairing-code", async (req, res) => {
    const { number } = req.body;
    const username = getUserFromCookie(req);
    if (!username) return res.json({ success: false, error: "Not logged in" });
    if (!number) return res.json({ success: false, error: "Phone number required" });

    let cleanNumber = number.replace(/[^0-9]/g, "");
    if (cleanNumber.length < 9 || cleanNumber.length > 15) {
        return res.json({ success: false, error: "Invalid phone number. Use international format without + (e.g., 919876543210)" });
    }

    const sessionId = generateId("sess_");
    const authPath = path.join(AUTH_DIR, sessionId);
    if (!fs.existsSync(authPath)) fs.mkdirSync(authPath);

    try {
        const { state, saveCreds } = await useMultiFileAuthState(authPath);
        const { version } = await fetchLatestBaileysVersion();

        const sock = makeWASocket({
            version,
            logger: pino({ level: "silent" }),
            printQRInTerminal: false,
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, pino({ level: "silent" })),
            },
            browser: Browsers.ubuntu("Chrome"),
            syncFullHistory: false,
            markOnlineOnConnect: true,
            connectTimeoutMs: 60000,
        });

        sock.ev.on("creds.update", saveCreds);
        await delay(2000);

        let pairCode = null;
        const pairPromise = sock.requestPairingCode(cleanNumber);
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Pairing code request timed out after 30 seconds")), 30000)
        );

        try {
            pairCode = await Promise.race([pairPromise, timeoutPromise]);
            console.log(`Ã¢Å“â€¦ Pairing code for ${cleanNumber}: ${pairCode}`);
        } catch (pairErr) {
            console.error("Ã¢ÂÅ’ Pairing code request failed:", pairErr.message);
            throw new Error(`Failed to request pairing code: ${pairErr.message}`);
        }

        if (!pairCode) throw new Error("No pairing code received from WhatsApp");

        const sessionObj = {
            sessionId,
            userId: username,
            number: cleanNumber,
            isConnected: false,
            client: sock,
            createdAt: new Date(),
            tasks: new Map(),
            qrCode: null,
        };
        userSessions.set(sessionId, sessionObj);
        if (!userToSessions.has(username)) userToSessions.set(username, []);
        userToSessions.get(username).push(sessionId);

        sock.ev.on("connection.update", (update) => {
            const { connection, lastDisconnect } = update;
            if (connection === "open") {
                console.log(`Ã¢Å“â€¦ Session ${sessionId} connected`);
                const sess = userSessions.get(sessionId);
                if (sess) sess.isConnected = true;
            }
            if (connection === "close") {
                const reason = lastDisconnect?.error?.output?.statusCode;
                const errorMsg = lastDisconnect?.error?.message || "";
                if (errorMsg.includes("Bad MAC") || errorMsg.includes("crypto")) {
                    console.log(`Ã¢Å¡ Ã¯Â¸Â Bad MAC error for session ${sessionId}, force reinitializing...`);
                    reinitializeWhatsAppSession(sessionId);
                } else if (reason !== DisconnectReason.loggedOut) {
                    console.log(`Session ${sessionId} disconnected, will reconnect...`);
                    setTimeout(() => {
                        initWhatsAppSession(sessionId, username, cleanNumber);
                    }, 5000);
                } else {
                    const sess = userSessions.get(sessionId);
                    if (sess) sess.isConnected = false;
                    userSessions.delete(sessionId);
                    const userSess = userToSessions.get(username) || [];
                    userToSessions.set(username, userSess.filter(id => id !== sessionId));
                    fs.rmSync(authPath, { recursive: true, force: true });
                }
            }
        });

        res.json({
            success: true,
            code: pairCode,
            sessionId: sessionId,
            message: "Pairing code generated successfully. Open WhatsApp Ã¢â€ â€™ Settings Ã¢â€ â€™ Linked Devices Ã¢â€ â€™ Link with phone number Ã¢â€ â€™ Enter this code."
        });

    } catch (err) {
        console.error("Ã¢ÂÅ’ Session creation error:", err);
        try {
            if (fs.existsSync(authPath)) fs.rmSync(authPath, { recursive: true, force: true });
        } catch (cleanErr) {}
        res.json({ success: false, error: err.message || "Failed to generate pairing code. Check number format and try again." });
    }
});

// ---------- RECONNECT HELPER ----------
async function initWhatsAppSession(sessionId, userId, phoneNumber) {
    const authPath = path.join(AUTH_DIR, sessionId);
    if (!fs.existsSync(authPath)) return;

    try {
        const { state, saveCreds } = await useMultiFileAuthState(authPath);
        const { version } = await fetchLatestBaileysVersion();

        const sock = makeWASocket({
            version,
            logger: pino({ level: "silent" }),
            printQRInTerminal: false,
            browser: Browsers.ubuntu("Chrome"),
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, pino({ level: "silent" })),
            },
            markOnlineOnConnect: true,
            connectTimeoutMs: 60000,
        });

        sock.ev.on("creds.update", saveCreds);
        sock.ev.on("connection.update", (update) => {
            const { connection, lastDisconnect } = update;
            if (connection === "open") {
                const sess = userSessions.get(sessionId);
                if (sess) {
                    sess.isConnected = true;
                    sess.client = sock;
                }
            }
            if (connection === "close") {
                const reason = lastDisconnect?.error?.output?.statusCode;
                const errorMsg = lastDisconnect?.error?.message || "";
                if (errorMsg.includes("Bad MAC") || errorMsg.includes("crypto")) {
                    console.log(`Ã¢Å¡ Ã¯Â¸Â Bad MAC in reconnect for ${sessionId}, reinit again...`);
                    reinitializeWhatsAppSession(sessionId);
                } else if (reason !== DisconnectReason.loggedOut) {
                    setTimeout(() => initWhatsAppSession(sessionId, userId, phoneNumber), 5000);
                } else {
                    userSessions.delete(sessionId);
                    const userSess = userToSessions.get(userId) || [];
                    userToSessions.set(userId, userSess.filter(id => id !== sessionId));
                    fs.rmSync(authPath, { recursive: true, force: true });
                }
            }
        });

        const existing = userSessions.get(sessionId);
        if (existing) {
            existing.client = sock;
            existing.isConnected = false;
        }
    } catch (err) {
        console.error(`Reconnect failed for ${sessionId}:`, err);
    }
}

// ---------- OTHER ENDPOINTS (unchanged) ----------
app.post("/signup", (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.json({ success: false, error: "All fields required" });
    if (users.has(username)) return res.json({ success: false, error: "Username taken" });
    users.set(username, {
        email,
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
    });
    setUserCookie(res, username);
    res.json({ success: true, redirect: "/dashboard" });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = users.get(username);
    if (!user || user.passwordHash !== hashPassword(password)) {
        return res.json({ success: false, error: "Invalid credentials" });
    }
    setUserCookie(res, username);
    res.json({ success: true, redirect: "/dashboard" });
});

app.post("/admin-login", (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && hashPassword(password) === ADMIN_PASS_HASH) {
        setAdminCookie(res);
        res.json({ success: true, redirect: "/admin-dashboard" });
    } else {
        res.json({ success: false, error: "Invalid admin credentials" });
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("user");
    res.clearCookie("admin");
    res.redirect("/");
});

app.get("/api/get-numbers", (req, res) => {
    const username = getUserFromCookie(req);
    if (!username) return res.json([]);
    const sessionIds = userToSessions.get(username) || [];
    const numbersMap = new Map();
    for (const sid of sessionIds) {
        const sess = userSessions.get(sid);
        if (sess) {
            const phone = sess.number;
            if (!numbersMap.has(phone)) numbersMap.set(phone, { number: phone, sessions: [] });
            numbersMap.get(phone).sessions.push({ sessionId: sid, isConnected: sess.isConnected });
        }
    }
    res.json(Array.from(numbersMap.values()));
});

app.get("/api/live-status", (req, res) => {
    const { sessionId } = req.query;
    const sess = userSessions.get(sessionId);
    if (!sess) return res.json({ error: "Session not found" });
    const tasks = Array.from(sess.tasks.values()).map(t => ({
        taskId: t.taskId,
        target: t.target,
        targetType: t.targetType,
        totalMessages: t.totalMessages,
        sentMessages: t.sentMessages,
        currentIndex: t.currentIndex,
        isSending: t.isSending,
        createdAtFormatted: t.startTime.toLocaleString(),
    }));
    res.json({
        number: sess.number,
        isConnected: sess.isConnected,
        createdAtFormatted: sess.createdAt.toLocaleString(),
        tasks,
    });
});

app.get("/api/live-logs", (req, res) => {
    const { sessionId, taskId } = req.query;
    const sess = userSessions.get(sessionId);
    if (!sess) return res.json({ error: "Session not found" });
    const task = sess.tasks.get(taskId);
    if (!task) return res.json({ error: "Task not found" });
    res.json({
        taskInfo: {
            sentMessages: task.sentMessages,
            totalMessages: task.totalMessages,
            isSending: task.isSending,
        },
        logs: task.logs || [],
    });
});

// ------------------ LOOPING (UNLIMITED REPEAT) SEND ENDPOINT ------------------
app.post("/send-message", upload.single("messageFile"), async (req, res) => {
    const { selectedSession, target, targetType, delaySec, prefix } = req.body;
    const file = req.file;
    if (!selectedSession || !target || !file || !delaySec) {
        return res.json({ success: false, error: "Missing fields" });
    }

    let sess = userSessions.get(selectedSession);
    if (!sess || !sess.client) return res.json({ success: false, error: "Session not active" });
    if (!sess.isConnected) return res.json({ success: false, error: "WhatsApp not connected" });

    const fileContent = fs.readFileSync(file.path, "utf8");
    const messages = fileContent.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (messages.length === 0) return res.json({ success: false, error: "No messages in file" });

    const taskId = generateId("task_");
    const taskInfo = {
        taskId,
        target,
        targetType,
        totalMessages: messages.length,
        sentMessages: 0,
        currentIndex: 0,
        isSending: true,
        startTime: new Date(),
        logs: [],
        stopRequested: false,
        sessionId: selectedSession,
        // Ã Â¤â€¡Ã Â¤Â¨Ã Â¥ÂÃ Â¤Â«Ã Â¤Â¿Ã Â¤Â¨Ã Â¤Â¿Ã Â¤Å¸ Ã Â¤Â²Ã Â¥â€šÃ Â¤Âª Ã Â¤â€¢Ã Â¥â€¡ Ã Â¤Â²Ã Â¤Â¿Ã Â¤Â, Ã Â¤Â¹Ã Â¤Â° Ã Â¤Â¬Ã Â¤Â¾Ã Â¤Â° Ã Â¤ÂªÃ Â¥â€šÃ Â¤Â°Ã Â¤Â¾ Ã Â¤Å¡Ã Â¤â€¢Ã Â¥ÂÃ Â¤Â° Ã Â¤â€“Ã Â¤Â¤Ã Â¥ÂÃ Â¤Â® Ã Â¤Â¹Ã Â¥â€¹Ã Â¤Â¨Ã Â¥â€¡ Ã Â¤ÂªÃ Â¤Â° Ã Â¤Â°Ã Â¥â‚¬Ã Â¤Â¸Ã Â¥â€¡Ã Â¤Å¸ Ã Â¤â€¢Ã Â¤Â°Ã Â¥â€¡Ã Â¤â€šÃ Â¤â€”Ã Â¥â€¡
    };
    sess.tasks.set(taskId, taskInfo);
    activeTasks.set(taskId, { sessionId: selectedSession, taskInfo });

    (async () => {
        const delayMs = parseInt(delaySec) * 1000;
        let cycleCount = 0;
        while (!taskInfo.stopRequested) {   // Ã Â¤â€¡Ã Â¤Â¨Ã Â¥ÂÃ Â¤Â«Ã Â¤Â¿Ã Â¤Â¨Ã Â¤Â¿Ã Â¤Å¸ Ã Â¤Â²Ã Â¥â€šÃ Â¤Âª (Ã Â¤Â¬Ã Â¤Â¾Ã Â¤Â°-Ã Â¤Â¬Ã Â¤Â¾Ã Â¤Â°)
            for (let i = 0; i < messages.length && !taskInfo.stopRequested; i++) {
                // Ã Â¤Â²Ã Â¤Â¾Ã Â¤â€¡Ã Â¤Âµ Ã Â¤Â¸Ã Â¥â€¡Ã Â¤Â¶Ã Â¤Â¨ Ã Â¤â€Ã Â¤Â° Ã Â¤â€¢Ã Â¥ÂÃ Â¤Â²Ã Â¤Â¾Ã Â¤â€¡Ã Â¤â€šÃ Â¤Å¸ Ã Â¤Â²Ã Â¥â€¡Ã Â¤â€š
                let currentSess = userSessions.get(selectedSession);
                let sock = currentSess?.client;

                // Ã Â¤â€¢Ã Â¤Â¨Ã Â¥â€¡Ã Â¤â€¢Ã Â¥ÂÃ Â¤Â¶Ã Â¤Â¨ Ã Â¤â€ Ã Â¤Â¨Ã Â¥â€¡ Ã Â¤Â¤Ã Â¤â€¢ Ã Â¤â€¡Ã Â¤â€šÃ Â¤Â¤Ã Â¤Å“Ã Â¤Â¼Ã Â¤Â¾Ã Â¤Â° (Bad MAC Ã Â¤Â°Ã Â¤Â¿Ã Â¤â€¢Ã Â¤ÂµÃ Â¤Â°Ã Â¥â‚¬ Ã Â¤â€¢Ã Â¥â€¡ Ã Â¤Â¬Ã Â¤Â¾Ã Â¤Â¦ Ã Â¤Â­Ã Â¥â‚¬)
                while (!sock || !currentSess?.isConnected) {
                    taskInfo.logs.push({ type: "warn", message: `Waiting for connection...`, details: "Session disconnected, will retry in 5 sec" });
                    await delay(5000);
                    currentSess = userSessions.get(selectedSession);
                    sock = currentSess?.client;
                    if (taskInfo.stopRequested) return;
                }

                let msg = messages[i];
                if (prefix) msg = prefix + " " + msg;
                try {
                    let jid = target;
                    if (targetType === "individual") {
                        jid = target.includes("@s.whatsapp.net") ? target : `${target}@s.whatsapp.net`;
                    } else {
                        jid = target.includes("@g.us") ? target : `${target}@g.us`;
                    }
                    await sock.sendMessage(jid, { text: msg });
                    taskInfo.sentMessages++;
                    taskInfo.currentIndex = i + 1;
                    taskInfo.logs.push({ type: "success", message: `Sent message ${i+1} (cycle ${cycleCount+1})`, details: msg.substring(0, 100) });
                } catch (err) {
                    const errMsg = err.message || "";
                    taskInfo.logs.push({ type: "error", message: `Failed message ${i+1} (cycle ${cycleCount+1})`, details: errMsg });
                    
                    if (errMsg.includes("Bad MAC") || errMsg.includes("crypto") || errMsg.includes("MAC")) {
                        taskInfo.logs.push({ type: "error", message: `Bad MAC error, reinitializing session...`, details: `Will retry message ${i+1}` });
                        await reinitializeWhatsAppSession(selectedSession);
                        i--; // same message retry
                        await delay(3000);
                        continue;
                    }
                    else if (errMsg.includes("connection") || errMsg.includes("closed") || errMsg.includes("timed out")) {
                        i--;
                        await delay(3000);
                        continue;
                    }
                }
                if (i < messages.length - 1 && !taskInfo.stopRequested) await delay(delayMs);
            }
            // Ã Â¤ÂÃ Â¤â€¢ Ã Â¤ÂªÃ Â¥â€šÃ Â¤Â°Ã Â¤Â¾ Ã Â¤Å¡Ã Â¤â€¢Ã Â¥ÂÃ Â¤Â° Ã Â¤â€“Ã Â¤Â¤Ã Â¥ÂÃ Â¤Â® Ã¢â‚¬â€œ Ã Â¤Â«Ã Â¤Â¿Ã Â¤Â° Ã Â¤Â¸Ã Â¥â€¡ Ã Â¤Â¶Ã Â¥ÂÃ Â¤Â°Ã Â¥â€š (Ã Â¤Â¯Ã Â¤Â¦Ã Â¤Â¿ stop Ã Â¤Â¨Ã Â¤Â¹Ã Â¥â‚¬Ã Â¤â€š Ã Â¤â€¢Ã Â¤Â¹Ã Â¤Â¾ Ã Â¤â€”Ã Â¤Â¯Ã Â¤Â¾)
            if (!taskInfo.stopRequested) {
                cycleCount++;
                taskInfo.logs.push({ type: "info", message: `Ã°Å¸â€â€ž Completed cycle ${cycleCount}, restarting from first message...`, details: "" });
                // currentIndex Ã Â¤â€Ã Â¤Â° sentMessages Ã Â¤â€¢Ã Â¥â€¹ Ã Â¤Â°Ã Â¥â‚¬Ã Â¤Â¸Ã Â¥â€¡Ã Â¤Å¸ Ã Â¤Â¨ Ã Â¤â€¢Ã Â¤Â°Ã Â¥â€¡Ã Â¤â€š, Ã Â¤Â¤Ã Â¤Â¾Ã Â¤â€¢Ã Â¤Â¿ Ã Â¤â€ Ã Â¤â€šÃ Â¤â€¢Ã Â¤Â¡Ã Â¤Â¼Ã Â¥â€¡ Ã Â¤Â¬Ã Â¤Â¢Ã Â¤Â¼Ã Â¤Â¤Ã Â¥â€¡ Ã Â¤Â°Ã Â¤Â¹Ã Â¥â€¡Ã Â¤â€š
                // Ã Â¤Â¬Ã Â¤Â¸ Ã Â¤â€¦Ã Â¤â€”Ã Â¤Â²Ã Â¤Â¾ for loop Ã Â¤Â«Ã Â¤Â¿Ã Â¤Â° Ã Â¤Â¸Ã Â¥â€¡ i=0 Ã Â¤Â¸Ã Â¥â€¡ Ã Â¤Å¡Ã Â¤Â²Ã Â¥â€¡Ã Â¤â€”Ã Â¤Â¾
                // Ã Â¤Â¥Ã Â¥â€¹Ã Â¤Â¡Ã Â¤Â¼Ã Â¤Â¾ Ã Â¤Â¸Ã Â¤Â¾ gap Ã Â¤Â²Ã Â¥â€¡ Ã Â¤Â¸Ã Â¤â€¢Ã Â¤Â¤Ã Â¥â€¡ Ã Â¤Â¹Ã Â¥Ë†Ã Â¤â€š, Ã Â¤Â²Ã Â¥â€¡Ã Â¤â€¢Ã Â¤Â¿Ã Â¤Â¨ Ã Â¤Â¨Ã Â¤Â¹Ã Â¥â‚¬Ã Â¤â€š Ã Â¤Â­Ã Â¥â‚¬
                await delay(delayMs); // Ã Â¤Â¥Ã Â¥â€¹Ã Â¤Â¡Ã Â¤Â¼Ã Â¤Â¾ Ã Â¤Â°Ã Â¥ÂÃ Â¤â€¢Ã Â¥â€¡Ã Â¤â€š Ã Â¤â€¦Ã Â¤â€”Ã Â¤Â²Ã Â¥â‚¬ Ã Â¤Â¸Ã Â¤Â¾Ã Â¤â€¡Ã Â¤â€¢Ã Â¤Â¿Ã Â¤Â² Ã Â¤Â¸Ã Â¥â€¡ Ã Â¤ÂªÃ Â¤Â¹Ã Â¤Â²Ã Â¥â€¡
            }
        }
        taskInfo.isSending = false;
        taskInfo.endTime = new Date();
        fs.unlink(file.path, () => {});
    })();

    res.json({ success: true, redirect: `/session-status?sessionId=${selectedSession}` });
});

// ---------- STOP SESSION / TASK (unchanged) ----------
app.post("/stop-session", async (req, res) => {
    const { sessionId } = req.body;
    const sess = userSessions.get(sessionId);
    if (!sess) return res.json({ success: false, error: "Session not found" });
    for (let [tid, task] of sess.tasks) task.stopRequested = true, task.isSending = false;
    if (sess.client) sess.client.end();
    userSessions.delete(sessionId);
    const userSess = userToSessions.get(sess.userId) || [];
    userToSessions.set(sess.userId, userSess.filter(id => id !== sessionId));
    const authPath = path.join(AUTH_DIR, sessionId);
    fs.rmSync(authPath, { recursive: true, force: true });
    res.json({ success: true, message: "Session deleted" });
});

app.post("/stop-task", (req, res) => {
    const { sessionId, taskId } = req.body;
    const sess = userSessions.get(sessionId);
    if (!sess) return res.json({ success: false, error: "Session not found" });
    const task = sess.tasks.get(taskId);
    if (!task) return res.json({ success: false, error: "Task not found" });
    task.stopRequested = true;
    task.isSending = false;
    res.json({ success: true, message: "Task stopped" });
});

app.get("/get-groups", async (req, res) => {
    const { sessionId } = req.query;
    const sess = userSessions.get(sessionId);
    if (!sess || !sess.client) return res.json({ success: false, error: "Session not active" });
    if (!sess.isConnected) return res.json({ success: false, error: "WhatsApp not connected" });
    try {
        const groups = [];
        const chats = await sess.client.groupFetchAllParticipating();
        for (let id in chats) {
            const chat = chats[id];
            groups.push({
                subject: chat.subject,
                groupId: id,
                participantsCount: chat.participants?.length || 0,
                creation: chat.creation ? new Date(chat.creation * 1000).toLocaleString() : null,
            });
        }
        res.json({ success: true, groups, number: sess.number });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

app.get("/api/admin/all-sessions", (req, res) => {
    if (!isAdmin(req)) return res.status(403).json([]);
    const all = [];
    for (let [sid, sess] of userSessions) {
        all.push({
            sessionId: sid,
            number: sess.number,
            username: sess.userId,
            isConnected: sess.isConnected,
            tasksCount: sess.tasks.size,
            activeTasksCount: Array.from(sess.tasks.values()).filter(t => t.isSending).length,
            createdAtFormatted: sess.createdAt.toLocaleString(),
        });
    }
    res.json(all);
});

app.get("/api/admin/session-details", (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
    const { sessionId } = req.query;
    const sess = userSessions.get(sessionId);
    if (!sess) return res.json({ error: "Session not found" });
    const tasks = Array.from(sess.tasks.values()).map(t => ({
        taskId: t.taskId,
        target: t.target,
        targetType: t.targetType,
        totalMessages: t.totalMessages,
        sentMessages: t.sentMessages,
        isSending: t.isSending,
        createdAtFormatted: t.startTime.toLocaleString(),
    }));
    res.json({
        sessionId,
        number: sess.number,
        username: sess.userId,
        isConnected: sess.isConnected,
        createdAtFormatted: sess.createdAt.toLocaleString(),
        tasks,
    });
});

app.get("/api/admin/task-logs", (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
    const { taskId } = req.query;
    for (let [sid, sess] of userSessions) {
        if (sess.tasks.has(taskId)) return res.json({ logs: sess.tasks.get(taskId).logs || [] });
    }
    res.json({ logs: [] });
});

app.post("/api/admin/delete-session", (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
    const { sessionId } = req.body;
    const sess = userSessions.get(sessionId);
    if (sess) {
        if (sess.client) sess.client.end();
        userSessions.delete(sessionId);
        const userSess = userToSessions.get(sess.userId) || [];
        userToSessions.set(sess.userId, userSess.filter(id => id !== sessionId));
        const authPath = path.join(AUTH_DIR, sessionId);
        fs.rmSync(authPath, { recursive: true, force: true });
    }
    res.json({ success: true });
});

app.post("/api/admin/delete-task", (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ error: "Unauthorized" });
    const { sessionId, taskId } = req.body;
    const sess = userSessions.get(sessionId);
    if (sess && sess.tasks.has(taskId)) {
        const task = sess.tasks.get(taskId);
        task.stopRequested = true;
        task.isSending = false;
        sess.tasks.delete(taskId);
    }
    res.json({ success: true });
});

app.get("/health", (req, res) => {
    const totalTasks = Array.from(userSessions.values()).reduce((acc, s) => acc + s.tasks.size, 0);
    const activeTasksCount = Array.from(userSessions.values()).reduce((acc, s) => {
        return acc + Array.from(s.tasks.values()).filter(t => t.isSending).length;
    }, 0);
    const memUsage = process.memoryUsage();
    res.json({
        status: "ok",
        sessions: userSessions.size,
        tasks: totalTasks,
        activeTasks: activeTasksCount,
        uptime: process.uptime().toFixed(1) + " sec",
        memory: {
            used: (memUsage.heapUsed / 1024 / 1024).toFixed(2) + " MB",
            total: (memUsage.heapTotal / 1024 / 1024).toFixed(2) + " MB",
        },
    });
});

// ---------- HTML (unchanged) ----------
const HTML_CONTENT = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
  <title>WhatsApp Server | Ashiq Raj</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); font-family: 'Inter', sans-serif; color: #f1f5f9; padding: 24px 16px; }
    .container { max-width: 1280px; margin: 0 auto; }
    .glass-box { background: rgba(30,41,59,0.65); backdrop-filter: blur(12px); border-radius: 2rem; padding: 28px 32px; margin: 24px 0; border: 1px solid rgba(56,189,248,0.4); }
    input, select, button { width: 100%; padding: 14px 20px; margin: 12px 0; background: #1e293b; border: 1.5px solid #334155; border-radius: 28px; color: white; font-size: 1rem; }
    button { background: #0ea5e9; cursor: pointer; font-weight: bold; }
    .status-connected { background: rgba(34,197,94,0.2); color: #4ade80; }
    .status-disconnected { background: rgba(239,68,68,0.2); color: #f87171; }
    .hidden { display: none; }
    .session-card, .task-card { background: #0f172a; border-radius: 1.5rem; padding: 20px; margin: 16px 0; border-left: 5px solid #38bdf8; }
    .status-badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 40px; font-size: 0.8rem; font-weight: 600; }
  </style>
</head>
<body>
<div class="container" id="app"></div>
<script>
  let statusInterval = null, logsInterval = null, uptimeTimer = null, numbersCache = [];
  async function apiCall(url, options = {}) {
    const res = await fetch(url, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...options.headers }, ...options });
    return res.json();
  }
  function showAlert(containerId, message) {
    const el = document.getElementById(containerId);
    if (el) { el.innerHTML = '<div style="background:#0f172a;padding:12px;border-radius:28px;">'+message+'</div>'; setTimeout(()=>el.innerHTML='',4000); }
  }
  async function updateUptimeDisplay() {
    try { const data = await apiCall('/health'); const div = document.getElementById('globalUptime'); if(div) div.innerHTML = '<i class="fas fa-clock"></i> Uptime: '+data.uptime; } catch(e) {}
  }
  function showLogin() {
    document.getElementById('app').innerHTML = \`
      <div id="globalUptime"></div>
      <h1>WhatsApp Server | Ashiq Raj</h1>
      <div class="glass-box">
        <h2>User Login</h2>
        <div id="loginAlert"></div>
        <input type="text" id="loginUsername" placeholder="Username">
        <input type="password" id="loginPassword" placeholder="Password">
        <button onclick="handleLogin()">Login</button>
        <p>New user? <a href="#" onclick="showSignup();return false;">Sign up</a> | <a href="#" onclick="showAdminLogin();return false;">Admin</a></p>
      </div>
    \`;
    updateUptimeDisplay();
  }
  async function handleLogin() {
    const res = await apiCall('/login', { method:'POST', body: JSON.stringify({ username:document.getElementById('loginUsername').value, password:document.getElementById('loginPassword').value }) });
    if(res.success) window.location.href = '/dashboard';
    else showAlert('loginAlert', res.error);
  }
  function showSignup() {
    document.getElementById('app').innerHTML = \`
      <div id="globalUptime"></div>
      <h1>Create Account</h1>
      <div class="glass-box">
        <h2>Sign Up</h2>
        <div id="signupAlert"></div>
        <input type="text" id="signupName" placeholder="Username">
        <input type="email" id="signupEmail" placeholder="Email">
        <input type="password" id="signupPass" placeholder="Password">
        <button onclick="handleSignup()">Register</button>
        <p>Already have account? <a href="#" onclick="showLogin();return false;">Login</a></p>
      </div>
    \`;
    updateUptimeDisplay();
  }
  async function handleSignup() {
    const res = await apiCall('/signup', { method:'POST', body: JSON.stringify({ username:document.getElementById('signupName').value, email:document.getElementById('signupEmail').value, password:document.getElementById('signupPass').value }) });
    if(res.success) window.location.href = '/dashboard';
    else showAlert('signupAlert', res.error);
  }
  function showAdminLogin() {
    document.getElementById('app').innerHTML = \`
      <div id="globalUptime"></div>
      <h1>Admin Portal</h1>
      <div class="glass-box">
        <h2>Administrator Access</h2>
        <div id="adminAlert"></div>
        <input type="text" id="adminUser" placeholder="Admin Username">
        <input type="password" id="adminPass" placeholder="Password">
        <button onclick="handleAdminLogin()">Authenticate</button>
        <p><a href="#" onclick="showLogin();return false;">Ã¢â€ Â Back to user login</a></p>
      </div>
    \`;
    updateUptimeDisplay();
  }
  async function handleAdminLogin() {
    const res = await apiCall('/admin-login', { method:'POST', body: JSON.stringify({ username:document.getElementById('adminUser').value, password:document.getElementById('adminPass').value }) });
    if(res.success) window.location.href = '/admin-dashboard';
    else showAlert('adminAlert', 'Invalid admin credentials');
  }
  async function showDashboard() {
    document.getElementById('app').innerHTML = \`
      <div id="globalUptime"></div>
      <h1>WhatsApp Control Panel</h1>
      <div class="glass-box">
        <h2>Generate Pairing Code</h2>
        <div id="pairAlert"></div>
        <input type="text" id="pairPhone" placeholder="Phone with country code (e.g., 919876543210)">
        <button onclick="generatePairing()">Generate Code</button>
        <div id="pairResult"></div>
        <a href="#" onclick="logout()" style="display:inline-block;margin-top:20px;background:#dc2626;padding:8px 20px;border-radius:40px;">Logout</a>
      </div>
      <div class="glass-box">
        <h2>My Sessions</h2>
        <button onclick="loadUserSessions()">Refresh</button>
        <div id="mySessionsList">Loading...</div>
      </div>
      <div class="glass-box">
        <h2>Bulk Message Sender</h2>
        <div id="sendMsgAlert"></div>
        <select id="senderNumberSelect" onchange="loadSenderSessions()"><option>-- Select Phone Number --</option></select>
        <select id="senderSessionSelect" class="hidden" onchange="showSendForm()"><option>-- Select Session --</option></select>
        <div id="sendFormPanel" class="hidden">
          <input type="text" id="targetId" placeholder="Target: Group ID or Phone">
          <select id="targetTypeSelect"><option value="individual">Individual</option><option value="group">WhatsApp Group</option></select>
          <input type="file" id="msgFile" accept=".txt">
          <input type="number" id="delaySec" placeholder="Delay (seconds)" min="1" value="5">
          <input type="text" id="msgPrefix" placeholder="Optional prefix">
          <button onclick="startBulkSend()">Start Sending</button>
        </div>
      </div>
      <div class="glass-box">
        <h2>Fetch WhatsApp Groups</h2>
        <select id="groupNumberSelect" onchange="loadGroupSessions()"><option>-- Select Phone Number --</option></select>
        <select id="groupSessionSelect" class="hidden"><option>-- Select Session --</option></select>
        <button id="fetchGroupsBtn" class="hidden" onclick="fetchGroups()">Show Groups</button>
        <div id="groupsDisplay"></div>
      </div>
    \`;
    updateUptimeDisplay();
    await loadPhoneNumbersForDropdowns();
    loadUserSessions();
  }
  async function loadPhoneNumbersForDropdowns() {
    const data = await apiCall('/api/get-numbers');
    numbersCache = data;
    const senderSelect = document.getElementById('senderNumberSelect');
    const groupSelect = document.getElementById('groupNumberSelect');
    if(senderSelect) senderSelect.innerHTML = '<option value="">-- Select Phone Number --</option>';
    if(groupSelect) groupSelect.innerHTML = '<option value="">-- Select Phone Number --</option>';
    data.forEach((item, idx) => {
      const opt = \`<option value="\${idx}">\${item.number} (\${item.sessions.length} session)</option>\`;
      if(senderSelect) senderSelect.innerHTML += opt;
      if(groupSelect) groupSelect.innerHTML += opt;
    });
  }
  function loadSenderSessions() {
    const idx = document.getElementById('senderNumberSelect').value;
    const sessionSelect = document.getElementById('senderSessionSelect');
    const sendPanel = document.getElementById('sendFormPanel');
    if(idx === "") { sessionSelect.classList.add('hidden'); sendPanel.classList.add('hidden'); return; }
    const sessions = numbersCache[idx]?.sessions || [];
    sessionSelect.innerHTML = '<option value="">-- Choose Session --</option>';
    sessions.forEach(s => { sessionSelect.innerHTML += \`<option value="\${s.sessionId}">\${s.sessionId.slice(0,12)}... (\${s.isConnected ? 'Ã¢Å“â€¦ Connected' : 'Ã¢Å¡ Ã¯Â¸Â Disconnected'})</option>\`; });
    sessionSelect.classList.remove('hidden');
    sendPanel.classList.add('hidden');
  }
  function showSendForm() {
    const sessionId = document.getElementById('senderSessionSelect').value;
    const panel = document.getElementById('sendFormPanel');
    if(sessionId) panel.classList.remove('hidden'); else panel.classList.add('hidden');
  }
  function loadGroupSessions() {
    const idx = document.getElementById('groupNumberSelect').value;
    const sessSel = document.getElementById('groupSessionSelect');
    const fetchBtn = document.getElementById('fetchGroupsBtn');
    if(idx === "") { sessSel.classList.add('hidden'); fetchBtn.classList.add('hidden'); return; }
    const sessions = numbersCache[idx]?.sessions || [];
    sessSel.innerHTML = '<option value="">-- Select Session --</option>';
    sessions.forEach(s => { sessSel.innerHTML += \`<option value="\${s.sessionId}">\${s.sessionId.slice(0,12)}...</option>\`; });
    sessSel.classList.remove('hidden');
    fetchBtn.classList.add('hidden');
    sessSel.onchange = () => { if(sessSel.value) fetchBtn.classList.remove('hidden'); else fetchBtn.classList.add('hidden'); };
  }
  async function fetchGroups() {
    const sessionId = document.getElementById('groupSessionSelect').value;
    const container = document.getElementById('groupsDisplay');
    if(!sessionId) return;
    container.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading groups...';
    try {
      const res = await fetch(\`/get-groups?sessionId=\${sessionId}\`);
      const data = await res.json();
      if(data.success && data.groups?.length) {
        let html = '<div><h3>Your Groups</h3>';
        data.groups.forEach(g => { html += \`<div style="background:#0f172a;border-radius:24px;padding:14px;margin-top:12px;"><strong>\${g.subject}</strong><br>\${g.groupId}<br>Participants: \${g.participantsCount}</div>\`; });
        html += '</div>';
        container.innerHTML = html;
      } else { container.innerHTML = '<p>No groups found or session not connected.</p>'; }
    } catch(e) { container.innerHTML = '<p>Error fetching groups</p>'; }
  }
  async function loadUserSessions() {
    const container = document.getElementById('mySessionsList');
    if(!container) return;
    container.innerHTML = '<i class="fas fa-spinner fa-pulse"></i> Fetching...';
    const data = await apiCall('/api/get-numbers');
    let html = '';
    for(let item of data) {
      for(let sess of item.sessions) {
        const statusData = await apiCall(\`/api/live-status?sessionId=\${sess.sessionId}\`);
        const tasks = statusData.tasks || [];
        const activeTasks = tasks.filter(t => t.isSending).length;
        html += \`<div class="session-card"><strong>\${item.number}</strong> <span class="status-badge \${statusData.isConnected ? 'status-connected' : 'status-disconnected'}">\${statusData.isConnected ? 'Connected' : 'Disconnected'}</span>
          <div>\${sess.sessionId.slice(0,16)}...</div><div>Tasks: \${tasks.length} (\${activeTasks} active)</div>
          <div><a href="#" onclick="viewSessionStatus('\${sess.sessionId}'); return false;">Monitor</a> | <a href="#" onclick="confirmDeleteSession('\${sess.sessionId}'); return false;" style="color:#f87171;">Delete</a></div></div>\`;
      }
    }
    if(html === '') html = '<p>No active sessions. Generate a pairing code to start.</p>';
    container.innerHTML = html;
  }
  async function viewSessionStatus(sessionId) {
    document.getElementById('app').innerHTML = \`
      <div id="globalUptime"></div>
      <h1>Session Monitor</h1>
      <div class="glass-box" id="sessionDetailsBox"></div>
      <div class="glass-box"><h2>Active Tasks</h2><div id="sessionTasksList"></div></div>
      <a href="#" onclick="showDashboard(); return false;">Ã¢â€ Â Back to Dashboard</a>
    \`;
    updateUptimeDisplay();
    await refreshSessionStatus(sessionId);
    if(statusInterval) clearInterval(statusInterval);
    statusInterval = setInterval(() => refreshSessionStatus(sessionId), 5000);
  }
  async function refreshSessionStatus(sessionId) {
    const data = await apiCall(\`/api/live-status?sessionId=\${sessionId}\`);
    const detailsDiv = document.getElementById('sessionDetailsBox');
    const tasksDiv = document.getElementById('sessionTasksList');
    if(detailsDiv) {
      detailsDiv.innerHTML = \`<p><strong>Number:</strong> \${data.number}</p><p><strong>Status:</strong> <span class="status-badge \${data.isConnected ? 'status-connected' : 'status-disconnected'}">\${data.isConnected ? 'Online' : 'Offline'}</span></p><p><strong>Created:</strong> \${data.createdAtFormatted}</p>\`;
    }
    if(tasksDiv && data.tasks) {
      if(data.tasks.length===0) tasksDiv.innerHTML = '<p>No tasks yet</p>';
      else {
        let tasksHtml = '';
        data.tasks.forEach(t => {
          tasksHtml += \`<div class="task-card"><strong>Target: \${t.target}</strong><br>\${t.sentMessages}/\${t.totalMessages} sent<br>Status: \${t.isSending ? 'Running' : 'Stopped'}<br>
          <a href="#" onclick="viewTaskLogs('\${sessionId}','\${t.taskId}'); return false;">Logs</a> | <a href="#" onclick="confirmStopTask('\${sessionId}','\${t.taskId}')" style="color:#f87171;">Stop</a></div>\`;
        });
        tasksDiv.innerHTML = tasksHtml;
      }
    }
  }
  async function viewTaskLogs(sessionId, taskId) {
    document.getElementById('app').innerHTML = \`
      <div id="globalUptime"></div>
      <h1>Task Logs</h1>
      <div class="glass-box"><div id="taskLogsContainer">Loading logs...</div></div>
      <a href="#" onclick="viewSessionStatus('\${sessionId}'); return false;">Ã¢â€ Â Back to Session</a>
    \`;
    updateUptimeDisplay();
    await refreshLogs(sessionId, taskId);
    if(logsInterval) clearInterval(logsInterval);
    logsInterval = setInterval(() => refreshLogs(sessionId, taskId), 4500);
  }
  async function refreshLogs(sessionId, taskId) {
    const data = await apiCall(\`/api/live-logs?sessionId=\${sessionId}&taskId=\${taskId}\`);
    const container = document.getElementById('taskLogsContainer');
    if(container && data.logs) {
      let html = \`<p>Progress: \${data.taskInfo?.sentMessages || 0}/\${data.taskInfo?.totalMessages || 0}</p><div style="max-height:400px;overflow:auto;">\`;
      data.logs.slice().reverse().forEach(l => {
        html += \`<div style="background:#0f172a;border-radius:20px;padding:12px;margin:8px 0;border-left:4px solid \${l.type==='success'?'#4ade80':l.type==='error'?'#f87171':'#38bdf8'}"><strong>\${l.message}</strong><br><small>\${l.details}</small></div>\`;
      });
      html += \`</div>\`;
      container.innerHTML = html;
    }
  }
  async function generatePairing() {
    const phone = document.getElementById('pairPhone').value;
    if(!phone) return showAlert('pairAlert','Enter phone number');
    showAlert('pairAlert','Generating...');
    const res = await apiCall('/generate-pairing-code', { method:'POST', body: JSON.stringify({ number:phone }) });
    if(res.success) {
      let html = \`<div><h3>Ã¢Å“â€¦ Session Created</h3><p>Session ID: \${res.sessionId}</p>\`;
      if(res.code) html += \`<p><strong>Pairing Code: \${res.code}</strong></p><p>Open WhatsApp Ã¢â€ â€™ Settings Ã¢â€ â€™ Linked Devices Ã¢â€ â€™ Link with phone number Ã¢â€ â€™ Enter this code.</p>\`;
      html += \`</div>\`;
      document.getElementById('pairResult').innerHTML = html;
      loadPhoneNumbersForDropdowns();
      loadUserSessions();
    } else showAlert('pairAlert', res.error);
  }
  async function startBulkSend() {
    const sessionId = document.getElementById('senderSessionSelect').value;
    const target = document.getElementById('targetId').value;
    const targetType = document.getElementById('targetTypeSelect').value;
    const delay = document.getElementById('delaySec').value;
    const prefix = document.getElementById('msgPrefix').value;
    const fileInput = document.getElementById('msgFile');
    if(!sessionId || !target || !fileInput.files.length) return showAlert('sendMsgAlert','Fill all fields and select .txt file');
    const formData = new FormData();
    formData.append('selectedSession', sessionId);
    formData.append('target', target);
    formData.append('targetType', targetType);
    formData.append('messageFile', fileInput.files[0]);
    formData.append('delaySec', delay);
    formData.append('prefix', prefix);
    showAlert('sendMsgAlert','Starting sending task...');
    const res = await fetch('/send-message', { method:'POST', body:formData });
    const data = await res.json();
    if(data.success) window.location.href = data.redirect;
    else showAlert('sendMsgAlert', data.error);
  }
  async function confirmDeleteSession(sessionId) {
    if(confirm('Delete this session permanently?')) {
      await apiCall('/stop-session', { method:'POST', body: JSON.stringify({ sessionId }) });
      loadUserSessions();
      loadPhoneNumbersForDropdowns();
    }
  }
  async function confirmStopTask(sessionId, taskId) {
    if(confirm('Stop this task?')) {
      await apiCall('/stop-task', { method:'POST', body: JSON.stringify({ sessionId, taskId }) });
      refreshSessionStatus(sessionId);
    }
  }
  function logout() { window.location.href = '/logout'; }
  async function showAdminDashboard() {
    document.getElementById('app').innerHTML = \`
      <div id="globalUptime"></div>
      <h1>Admin Control</h1>
      <div class="glass-box"><h2>System Stats</h2><div id="adminStats"></div><a href="#" onclick="logout()" style="background:#dc2626;padding:8px 20px;border-radius:40px;">Logout</a></div>
      <div class="glass-box"><h2>All User Sessions</h2><button onclick="loadAllSessionsAdmin()">Refresh</button><div id="adminSessionsList"></div></div>
    \`;
    updateUptimeDisplay();
    loadAdminStats();
    loadAllSessionsAdmin();
  }
  async function loadAdminStats() {
    const health = await apiCall('/health');
    document.getElementById('adminStats').innerHTML = \`<p>Sessions: \${health.sessions} | Tasks: \${health.tasks} | Active: \${health.activeTasks}</p><p>Memory: \${health.memory?.used}</p><p>Uptime: \${health.uptime}</p>\`;
  }
  async function loadAllSessionsAdmin() {
    const sessions = await apiCall('/api/admin/all-sessions');
    let html = '';
    sessions.forEach(s => {
      html += \`<div class="session-card"><strong>\${s.number}</strong> | User: \${s.username} | Status: \${s.isConnected ? 'Ã°Å¸Å¸Â¢' : 'Ã°Å¸â€Â´'}<br> Tasks: \${s.tasksCount} (\${s.activeTasksCount} active)<br><a href="#" onclick="adminViewSession('\${s.sessionId}')">Details</a> | <a href="#" onclick="adminDeleteSession('\${s.sessionId}')" style="color:#f87171;">Delete</a></div>\`;
    });
    document.getElementById('adminSessionsList').innerHTML = html || '<p>No sessions</p>';
  }
  window.adminViewSession = async (sessionId) => {
    const data = await apiCall(\`/api/admin/session-details?sessionId=\${sessionId}\`);
    let tasksHtml = '';
    data.tasks?.forEach(t => { tasksHtml += \`<div>\${t.target} - \${t.sentMessages}/\${t.totalMessages} <a href="#" onclick="adminViewTaskLogs('\${t.taskId}')">logs</a> <a href="#" onclick="adminDeleteTask('\${sessionId}','\${t.taskId}')">Ã¢ÂÅ’</a></div>\`; });
    alert(\`Session: \${data.number}\\nUser: \${data.username}\\nTasks:\\n\${tasksHtml || 'No tasks'}\`);
  };
  window.adminViewTaskLogs = async (taskId) => { const logs = await apiCall(\`/api/admin/task-logs?taskId=\${taskId}\`); alert(logs.logs?.slice(0,5).map(l=>l.message).join('\\n')||'No logs'); };
  window.adminDeleteSession = async (sessionId) => { if(confirm('Delete session for all users?')){ await apiCall('/api/admin/delete-session',{method:'POST',body:JSON.stringify({sessionId})}); loadAllSessionsAdmin(); } };
  window.adminDeleteTask = async (sessionId,taskId) => { await apiCall('/api/admin/delete-task',{method:'POST',body:JSON.stringify({sessionId,taskId})}); loadAllSessionsAdmin(); };
  
  function router() {
    const pathname = window.location.pathname;
    const params = new URLSearchParams(window.location.search);
    if (pathname === '/session-status') {
      const sessionId = params.get('sessionId');
      if (sessionId) viewSessionStatus(sessionId);
      else showLogin();
    } else if (pathname === '/' || pathname === '/login') showLogin();
    else if (pathname === '/signup') showSignup();
    else if (pathname === '/admin-login') showAdminLogin();
    else if (pathname === '/dashboard') showDashboard();
    else if (pathname === '/admin-dashboard') showAdminDashboard();
    else showLogin();
  }
  window.addEventListener('popstate', router);
  router();
  setInterval(updateUptimeDisplay, 10000);
</script>
</body>
</html>`;

fs.writeFileSync(path.join(PUBLIC_DIR, "index.html"), HTML_CONTENT);

app.get("*", (req, res) => {
    res.sendFile("index.html", { root: PUBLIC_DIR });
});

// Ã Â¤â€”Ã Â¥ÂÃ Â¤Â²Ã Â¥â€¹Ã Â¤Â¬Ã Â¤Â² Ã Â¤ÂÃ Â¤Â°Ã Â¤Â° Ã Â¤Â¹Ã Â¥Ë†Ã Â¤â€šÃ Â¤Â¡Ã Â¤Â²Ã Â¤Â° (Ã Â¤Â¸Ã Â¤Â°Ã Â¥ÂÃ Â¤ÂµÃ Â¤Â° Ã Â¤â€¢Ã Â¥ÂÃ Â¤Â°Ã Â¥Ë†Ã Â¤Â¶ Ã Â¤Â¸Ã Â¥â€¡ Ã Â¤Â¬Ã Â¤Å¡Ã Â¤Â¨Ã Â¥â€¡ Ã Â¤â€¢Ã Â¥â€¡ Ã Â¤Â²Ã Â¤Â¿Ã Â¤Â)
process.on('uncaughtException', (err) => {
    if (err.message && (err.message.includes('Bad MAC') || err.message.includes('crypto'))) {
        console.error('Ã¢Å¡ Ã¯Â¸Â Uncaught Bad MAC error (ignored):', err.message);
    } else {
        console.error('Uncaught Exception:', err);
    }
});
process.on('unhandledRejection', (reason, promise) => {
    const errMsg = reason?.message || String(reason);
    if (errMsg.includes('Bad MAC') || errMsg.includes('crypto')) {
        console.error('Ã¢Å¡ Ã¯Â¸Â Unhandled Bad MAC rejection (ignored):', errMsg);
    } else {
        console.error('Unhandled Rejection:', reason);
    }
});

app.listen(PORT, () => {
    console.log(`Ã°Å¸Å¡â‚¬ WhatsApp Server running on http://localhost:${PORT}`);
    console.log(`Ã°Å¸â€˜â€˜ Admin login: arjun / arjun`);
    console.log(`Ã°Å¸â€œÂ± User signup/login: any username/password`);
    console.log(`Ã°Å¸Å’Â Works for all countries Ã¢â‚¬â€œ use international format without + (e.g., 919876543210)`);
});