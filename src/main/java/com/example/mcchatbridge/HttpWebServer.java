package com.example.mcchatbridge;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HttpWebServer {
    private static HttpServer server;
    private static final List<HttpExchange> clients = new CopyOnWriteArrayList<>();
    private static final List<ChatMessage> history = Collections.synchronizedList(new ArrayList<>());
    private static final List<PrivateMessage> privateHistory = Collections.synchronizedList(new ArrayList<>());
    
    private static final File HISTORY_FILE = new File("config/mcchatbridge_history.txt");
    private static final File PRIVATE_HISTORY_FILE = new File("config/mcchatbridge_private.txt");
    
    private static ExecutorService executor;
    private static Thread heartbeatThread;

    private static final File CONFIG_FILE = new File("config/mcchatbridge.json");
    public static ModConfig config = new ModConfig();

    // AES-256-GCM encryption for private message history
    private static final File KEY_FILE = new File("config/mcchatbridge_key.bin");
    private static SecretKey privateKey = null;

    public static class ModConfig {
        public int port = 8080;
        public boolean clickerEnabled = true;
        public boolean allowImageUploads = true;
        public List<OreConfig> ores = new ArrayList<>();

        public static class OreConfig {
            public String id;
            public String itemId;
            public String name;
            public String color;
            public int hits;
            public double weight;

            public OreConfig(String id, String itemId, String name, String color, int hits, double weight) {
                this.id = id;
                this.itemId = itemId;
                this.name = name;
                this.color = color;
                this.hits = hits;
                this.weight = weight;
            }
        }
    }

    public static void loadConfig() {
        if (!CONFIG_FILE.exists()) {
            config.port = 8080;
            config.clickerEnabled = true;
            config.allowImageUploads = true;
            config.ores.add(new ModConfig.OreConfig("coal", "minecraft:coal", "Coal", "#707070", 7, 30.0));
            config.ores.add(new ModConfig.OreConfig("lapis", "minecraft:lapis_lazuli", "Lapis", "#1010a0", 8, 25.0));
            config.ores.add(new ModConfig.OreConfig("redstone", "minecraft:redstone", "Redstone", "#ff0000", 8, 25.0));
            config.ores.add(new ModConfig.OreConfig("iron", "minecraft:iron_ingot", "Iron", "#d8af93", 8, 14.0));
            config.ores.add(new ModConfig.OreConfig("diamond", "minecraft:diamond", "Diamond", "#55ffff", 10, 5.8));
            config.ores.add(new ModConfig.OreConfig("netherite", "minecraft:netherite_block", "Netherite Block", "#312c36", 500, 0.005));
            saveConfig();
            return;
        }

        try (Reader reader = new FileReader(CONFIG_FILE, StandardCharsets.UTF_8)) {
            config = new com.google.gson.Gson().fromJson(reader, ModConfig.class);
            if (config == null) {
                config = new ModConfig();
            }
        } catch (Exception e) {
            System.err.println("[McChatBridge] Error loading config: " + e.getMessage());
        }
    }

    public static void saveConfig() {
        CONFIG_FILE.getParentFile().mkdirs();
        try (Writer writer = new FileWriter(CONFIG_FILE, StandardCharsets.UTF_8)) {
            new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(config, writer);
        } catch (Exception e) {
            System.err.println("[McChatBridge] Error saving config: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Private message encryption (AES-256-GCM)
    // -------------------------------------------------------------------------

    private static void loadOrGenerateKey() {
        if (KEY_FILE.exists()) {
            try {
                byte[] keyBytes = Files.readAllBytes(KEY_FILE.toPath());
                privateKey = new SecretKeySpec(keyBytes, "AES");
                System.out.println("[McChatBridge] Private message encryption key loaded.");
            } catch (Exception e) {
                System.err.println("[McChatBridge] Failed to load encryption key, generating new one: " + e.getMessage());
                generateNewKey();
            }
        } else {
            generateNewKey();
        }
    }

    private static void generateNewKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, new SecureRandom());
            privateKey = keyGen.generateKey();
            KEY_FILE.getParentFile().mkdirs();
            Files.write(KEY_FILE.toPath(), privateKey.getEncoded());
            System.out.println("[McChatBridge] New AES-256 encryption key generated and saved.");
        } catch (Exception e) {
            System.err.println("[McChatBridge] Failed to generate encryption key: " + e.getMessage());
            privateKey = null;
        }
    }

    /**
     * Encrypts a plaintext line using AES-256-GCM.
     * Output format: base64(IV):base64(ciphertext)
     * Each call uses a fresh random 12-byte IV.
     */
    private static String encryptLine(String plaintext) {
        if (privateKey == null) return plaintext; // fallback: no key available
        try {
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey, new GCMParameterSpec(128, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ciphertext);
        } catch (Exception e) {
            System.err.println("[McChatBridge] Encryption failed: " + e.getMessage());
            return plaintext;
        }
    }

    /**
     * Decrypts a line previously encrypted by encryptLine().
     * Returns null if decryption fails (e.g. corrupted data or wrong key).
     */
    private static String decryptLine(String encrypted) {
        if (privateKey == null || encrypted == null || encrypted.isEmpty()) return null;
        try {
            String[] parts = encrypted.split(":", 2);
            if (parts.length != 2) return null;
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[1]);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey, new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null; // decryption failed — corrupted or old plaintext line
        }
    }

    public static class WebSession {
        String nick;
        HttpExchange exchange;
        final java.util.concurrent.CountDownLatch closeLatch = new java.util.concurrent.CountDownLatch(1);
        WebSession(String nick, HttpExchange exchange) {
            this.nick = nick;
            this.exchange = exchange;
        }
    }
    private static final List<WebSession> webSessions = new CopyOnWriteArrayList<>();

    public static class ChatMessage {
        String sender;
        String text;
        long time;
        boolean isWeb;

        public ChatMessage(String sender, String text, long time, boolean isWeb) {
            this.sender = sender;
            this.text = text;
            this.time = time;
            this.isWeb = isWeb;
        }
    }

    public static class PrivateMessage {
        String from;
        String to;
        String text;
        long time;

        public PrivateMessage(String from, String to, String text, long time) {
            this.from = from;
            this.to = to;
            this.text = text;
            this.time = time;
        }
    }

    public static void start(int defaultPort) {
        loadConfig();
        loadOrGenerateKey();
        if (config.port <= 0) {
            config.port = defaultPort > 0 ? defaultPort : 8080;
        }
        int activePort = config.port;
        loadHistory();
        loadPrivateHistory();
        loadClicker();
        loadFurnaces();
        loadAccounts();
        loadSessions();
        try {
            executor = Executors.newCachedThreadPool();
            server = HttpServer.create(new InetSocketAddress(activePort), 0);
            server.setExecutor(executor);

            server.createContext("/", new IndexHandler());
            server.createContext("/auth/register", new RegisterHandler());
            server.createContext("/auth/login", new LoginHandler());
            server.createContext("/auth/logout", new LogoutHandler());
            server.createContext("/auth/me", new MeHandler());
            server.createContext("/stream", new StreamHandler());
            server.createContext("/send", new SendHandler());
            server.createContext("/leave", new LeaveHandler());
            server.createContext("/history", new HistoryHandler());
            server.createContext("/server-info", new ServerInfoHandler());
            server.createContext("/server-icon.png", new IconHandler());
            server.createContext("/notify.wav", new NotifySoundHandler());
            server.createContext("/players", new PlayersHandler());
            server.createContext("/minecraft-panorama.jpg", new PanoramaHandler());
            server.createContext("/private/send", new PrivateSendHandler());
            server.createContext("/private/history", new PrivateHistoryHandler());
            server.createContext("/upload", new UploadHandler());
            server.createContext("/uploads/", new ServeUploadsHandler());
            server.createContext("/avatar/upload", new AvatarUploadHandler());
            server.createContext("/avatar/", new AvatarServeHandler());
            server.createContext("/clicker/status", new ClickerStatusHandler());
            server.createContext("/clicker/click", new ClickerClickHandler());
            server.createContext("/clicker/transfer", new ClickerTransferHandler());
            server.createContext("/clicker/furnace/status", new ClickerFurnaceStatusHandler());
            server.createContext("/clicker/furnace/add", new ClickerFurnaceAddHandler());
            server.createContext("/clicker/furnace/take", new ClickerFurnaceTakeHandler());
            server.createContext("/clicker/textures.js", new ClickerTexturesHandler());

            server.start();
            System.out.println("[McChatBridge] Web Server started on port " + activePort);

            heartbeatThread = new Thread(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(5000);
                        sendPing();
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            });
            heartbeatThread.setDaemon(true);
            heartbeatThread.start();

        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to start Web Server: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void stop() {
        saveHistory();
        savePrivateHistory();
        saveClicker();
        saveFurnaces();
        if (heartbeatThread != null) {
            heartbeatThread.interrupt();
            heartbeatThread = null;
        }
        
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        for (WebSession session : webSessions) {
            session.closeLatch.countDown();
        }
        for (HttpExchange exchange : clients) {
            try {
                exchange.close();
            } catch (Exception ignored) {}
        }
        clients.clear();
        webSessions.clear();
        history.clear();
        privateHistory.clear();
        System.out.println("[McChatBridge] Web Server stopped");
    }

    private static void sendPing() {
        if (clients.isEmpty()) return;
        byte[] pingBytes = "event: ping\ndata: \n\n".getBytes(StandardCharsets.UTF_8);
        List<HttpExchange> toRemove = new ArrayList<>();
        for (HttpExchange exchange : clients) {
            try {
                OutputStream os = exchange.getResponseBody();
                os.write(pingBytes);
                os.flush();
            } catch (IOException e) {
                toRemove.add(exchange);
            }
        }
        if (!toRemove.isEmpty()) {
            clients.removeAll(toRemove);
            List<WebSession> sessionsToRemove = new ArrayList<>();
            for (WebSession session : webSessions) {
                if (toRemove.contains(session.exchange)) {
                    sessionsToRemove.add(session);
                }
            }
            webSessions.removeAll(sessionsToRemove);
            
            for (WebSession session : sessionsToRemove) {
                session.closeLatch.countDown();
                broadcastToWeb("[Server]", "§c" + session.nick + " (Web) left the chat", false);
            }

            for (HttpExchange exchange : toRemove) {
                try {
                    exchange.close();
                } catch (Exception ignored) {}
            }
        }
    }

    public static void broadcastToWeb(String sender, String text, boolean isWeb) {
        long time = System.currentTimeMillis();
        
        synchronized (history) {
            history.add(new ChatMessage(sender, text, time, isWeb));
            if (history.size() > 150) {
                history.remove(0);
            }
        }
        saveHistory();

        String json = String.format("{\"id\":\"%s\",\"sender\":\"%s\",\"text\":\"%s\",\"time\":%d,\"isWeb\":%b}",
                UUID.randomUUID().toString(),
                escapeJson(sender),
                escapeJson(text),
                time,
                isWeb
        );
        String eventData = "data: " + json + "\n\n";
        byte[] bytes = eventData.getBytes(StandardCharsets.UTF_8);

        List<HttpExchange> toRemove = new ArrayList<>();
        for (HttpExchange exchange : clients) {
            try {
                OutputStream os = exchange.getResponseBody();
                os.write(bytes);
                os.flush();
            } catch (IOException e) {
                toRemove.add(exchange);
            }
        }
        if (!toRemove.isEmpty()) {
            clients.removeAll(toRemove);
            
            List<WebSession> sessionsToRemove = new ArrayList<>();
            for (WebSession session : webSessions) {
                if (toRemove.contains(session.exchange)) {
                    sessionsToRemove.add(session);
                }
            }
            webSessions.removeAll(sessionsToRemove);
            
            for (WebSession session : sessionsToRemove) {
                session.closeLatch.countDown();
                broadcastToWeb("[Server]", "§c" + session.nick + " (Web) left the chat", false);
            }

            for (HttpExchange exchange : toRemove) {
                try {
                    exchange.close();
                } catch (Exception ignored) {}
            }
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("|", "%7C").replace("\n", "%0A").replace("\r", "%0D");
    }

    private static String unescape(String s) {
        if (s == null) return "";
        return s.replace("%7C", "|").replace("%0A", "\n").replace("%0D", "\r");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static void loadHistory() {
        if (!HISTORY_FILE.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(HISTORY_FILE, StandardCharsets.UTF_8))) {
            String line;
            synchronized (history) {
                history.clear();
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\\|", 4);
                    if (parts.length >= 3) {
                        try {
                            long time = Long.parseLong(parts[0]);
                            String sender = unescape(parts[1]);
                            String text = unescape(parts[2]);
                            boolean isWeb = (parts.length == 4) && "true".equalsIgnoreCase(parts[3]);
                            history.add(new ChatMessage(sender, text, time, isWeb));
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            System.out.println("[McChatBridge] Loaded " + history.size() + " messages from history.");
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to load history: " + e.getMessage());
        }
    }

    private static synchronized void saveHistory() {
        try {
            File parent = HISTORY_FILE.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(HISTORY_FILE, StandardCharsets.UTF_8))) {
                synchronized (history) {
                    int start = Math.max(0, history.size() - 100);
                    for (int i = start; i < history.size(); i++) {
                        ChatMessage msg = history.get(i);
                        writer.write(msg.time + "|" + escape(msg.sender) + "|" + escape(msg.text) + "|" + msg.isWeb);
                        writer.newLine();
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to save history: " + e.getMessage());
        }
    }

    private static void loadPrivateHistory() {
        if (!PRIVATE_HISTORY_FILE.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(PRIVATE_HISTORY_FILE, StandardCharsets.UTF_8))) {
            String line;
            synchronized (privateHistory) {
                privateHistory.clear();
                while ((line = reader.readLine()) != null) {
                    String decrypted = decryptLine(line);
                    if (decrypted == null) continue; // skip corrupted or old plaintext lines
                    String[] parts = decrypted.split("\\|", 4);
                    if (parts.length == 4) {
                        try {
                            long time = Long.parseLong(parts[0]);
                            String from = unescape(parts[1]);
                            String to = unescape(parts[2]);
                            String text = unescape(parts[3]);
                            privateHistory.add(new PrivateMessage(from, to, text, time));
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            System.out.println("[McChatBridge] Loaded " + privateHistory.size() + " private messages (encrypted).");
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to load private history: " + e.getMessage());
        }
    }

    private static synchronized void savePrivateHistory() {
        try {
            File parent = PRIVATE_HISTORY_FILE.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(PRIVATE_HISTORY_FILE, StandardCharsets.UTF_8))) {
                synchronized (privateHistory) {
                    int start = Math.max(0, privateHistory.size() - 500);
                    for (int i = start; i < privateHistory.size(); i++) {
                        PrivateMessage msg = privateHistory.get(i);
                        String plainLine = msg.time + "|" + escape(msg.from) + "|" + escape(msg.to) + "|" + escape(msg.text);
                        writer.write(encryptLine(plainLine));
                        writer.newLine();
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to save private history: " + e.getMessage());
        }
    }

    public static String getOnlinePlayersJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        int count = 0;
        
        if (com.example.mcchatbridge.McChatBridge.server != null) {
            try {
                Object[] players = com.example.mcchatbridge.McChatBridge.server.getPlayerList().getPlayers().toArray();
                for (int i = 0; i < players.length; i++) {
                    net.minecraft.server.level.ServerPlayer player = (net.minecraft.server.level.ServerPlayer) players[i];
                    if (count > 0) sb.append(",");
                    sb.append(String.format("{\"name\":\"%s\",\"uuid\":\"%s\",\"isWeb\":false}",
                            player.getGameProfile().getName(),
                            player.getUUID().toString()
                    ));
                    count++;
                }
            } catch (Exception ignored) {}
        }
        
        List<String> addedWebNicks = new ArrayList<>();
        for (WebSession session : webSessions) {
            boolean existsInMc = false;
            if (com.example.mcchatbridge.McChatBridge.server != null) {
                try {
                    Object[] players = com.example.mcchatbridge.McChatBridge.server.getPlayerList().getPlayers().toArray();
                    for (Object p : players) {
                        net.minecraft.server.level.ServerPlayer mp = (net.minecraft.server.level.ServerPlayer) p;
                        if (mp.getGameProfile().getName().equalsIgnoreCase(session.nick)) {
                            existsInMc = true;
                            break;
                        }
                    }
                } catch (Exception ignored) {}
            }
            if (!existsInMc && !addedWebNicks.contains(session.nick)) {
                addedWebNicks.add(session.nick);
                if (count > 0) sb.append(",");
                sb.append(String.format("{\"name\":\"%s\",\"uuid\":\"web-%s\",\"isWeb\":true}",
                        session.nick,
                        session.nick
                ));
                count++;
            }
        }
        
        sb.append("]");
        return sb.toString();
    }

    // ==================== Authentication / Accounts ====================

    private static final File ACCOUNTS_FILE = new File("config/mcchatbridge_accounts.json");
    private static final File SESSIONS_FILE = new File("config/mcchatbridge_sessions.json");
    private static final java.util.Map<String, Account> accounts = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Map<String, Session> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Map<String, RateInfo> loginRate = new java.util.concurrent.ConcurrentHashMap<>();
    private static final long SESSION_TTL_MS = 7L * 24 * 60 * 60 * 1000; // 7 days
    private static final int PBKDF2_ITERATIONS = 210000;
    private static final long RATE_WINDOW_MS = 15L * 60 * 1000;
    private static final int RATE_MAX_FAILS = 5;
    private static final int MAX_AVATAR_BYTES = 2 * 1024 * 1024; // 2 MB

    public static class Account {
        public String nick;
        public String salt;       // base64
        public String hash;       // base64 PBKDF2 output
        public int iterations;
        public long created;
    }
    public static class Session {
        public String nick;
        public long expiry;
    }
    private static class RateInfo {
        int fails;
        long windowStart;
        long lockedUntil;
    }

    private static String pbkdf2(String password, byte[] salt, int iterations) {
        try {
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, iterations, 256);
            javax.crypto.SecretKeyFactory f = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = f.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed", e);
        }
    }
    private static boolean verifyPassword(String password, Account acc) {
        byte[] salt = Base64.getDecoder().decode(acc.salt);
        String computed = pbkdf2(password, salt, acc.iterations);
        // constant-time comparison
        return java.security.MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.UTF_8),
                acc.hash.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean isValidNick(String nick) {
        return nick != null && nick.matches("^[A-Za-z0-9_]{3,16}$");
    }

    private static void loadAccounts() {
        if (!ACCOUNTS_FILE.exists()) return;
        try (Reader r = new FileReader(ACCOUNTS_FILE, StandardCharsets.UTF_8)) {
            java.lang.reflect.Type t = new com.google.gson.reflect.TypeToken<java.util.Map<String, Account>>(){}.getType();
            java.util.Map<String, Account> loaded = new com.google.gson.Gson().fromJson(r, t);
            if (loaded != null) { accounts.clear(); accounts.putAll(loaded); }
        } catch (Exception e) {
            System.err.println("[McChatBridge] Failed to load accounts: " + e.getMessage());
        }
    }
    private static synchronized void saveAccounts() {
        try (Writer w = new FileWriter(ACCOUNTS_FILE, StandardCharsets.UTF_8)) {
            new com.google.gson.Gson().toJson(accounts, w);
        } catch (Exception e) {
            System.err.println("[McChatBridge] Failed to save accounts: " + e.getMessage());
        }
    }
    private static void loadSessions() {
        if (!SESSIONS_FILE.exists()) return;
        try (Reader r = new FileReader(SESSIONS_FILE, StandardCharsets.UTF_8)) {
            java.lang.reflect.Type t = new com.google.gson.reflect.TypeToken<java.util.Map<String, Session>>(){}.getType();
            java.util.Map<String, Session> loaded = new com.google.gson.Gson().fromJson(r, t);
            if (loaded != null) {
                long now = System.currentTimeMillis();
                for (java.util.Map.Entry<String, Session> e : loaded.entrySet()) {
                    if (e.getValue() != null && e.getValue().expiry > now) sessions.put(e.getKey(), e.getValue());
                }
            }
        } catch (Exception e) {
            System.err.println("[McChatBridge] Failed to load sessions: " + e.getMessage());
        }
    }
    private static synchronized void saveSessions() {
        try (Writer w = new FileWriter(SESSIONS_FILE, StandardCharsets.UTF_8)) {
            new com.google.gson.Gson().toJson(sessions, w);
        } catch (Exception e) {
            System.err.println("[McChatBridge] Failed to save sessions: " + e.getMessage());
        }
    }

    private static String getCookie(HttpExchange ex, String name) {
        List<String> cookies = ex.getRequestHeaders().get("Cookie");
        if (cookies == null) return null;
        for (String header : cookies) {
            for (String part : header.split(";")) {
                String p = part.trim();
                if (p.startsWith(name + "=")) return p.substring(name.length() + 1);
            }
        }
        return null;
    }
    // Returns the authenticated display nick for this request, or null if not logged in.
    private static String sessionNick(HttpExchange ex) {
        String token = getCookie(ex, "mcb_session");
        if (token == null) return null;
        Session s = sessions.get(token);
        if (s == null) return null;
        if (s.expiry < System.currentTimeMillis()) { sessions.remove(token); return null; }
        return s.nick;
    }
    private static String createSession(String nick) {
        byte[] tok = new byte[32];
        new SecureRandom().nextBytes(tok);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tok);
        Session s = new Session();
        s.nick = nick;
        s.expiry = System.currentTimeMillis() + SESSION_TTL_MS;
        sessions.put(token, s);
        saveSessions();
        return token;
    }
    private static void setSessionCookie(HttpExchange ex, String token) {
        ex.getResponseHeaders().add("Set-Cookie",
                "mcb_session=" + token + "; Max-Age=" + (SESSION_TTL_MS / 1000) + "; Path=/; HttpOnly; SameSite=Lax");
    }
    private static void clearSessionCookie(HttpExchange ex) {
        ex.getResponseHeaders().add("Set-Cookie", "mcb_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
    }

    private static String clientIp(HttpExchange ex) {
        return ex.getRemoteAddress() != null ? ex.getRemoteAddress().getAddress().getHostAddress() : "unknown";
    }
    // returns seconds-to-wait if locked out, or 0 if a login attempt is allowed
    private static long rateCheck(String ip) {
        long now = System.currentTimeMillis();
        RateInfo r = loginRate.computeIfAbsent(ip, k -> new RateInfo());
        synchronized (r) {
            if (r.lockedUntil > now) return (r.lockedUntil - now) / 1000 + 1;
            if (now - r.windowStart > RATE_WINDOW_MS) { r.windowStart = now; r.fails = 0; }
            return 0;
        }
    }
    private static void rateFail(String ip) {
        long now = System.currentTimeMillis();
        RateInfo r = loginRate.computeIfAbsent(ip, k -> new RateInfo());
        synchronized (r) {
            if (now - r.windowStart > RATE_WINDOW_MS) { r.windowStart = now; r.fails = 0; }
            r.fails++;
            if (r.fails >= RATE_MAX_FAILS) r.lockedUntil = now + RATE_WINDOW_MS;
        }
    }
    private static void rateReset(String ip) {
        RateInfo r = loginRate.get(ip);
        if (r != null) synchronized (r) { r.fails = 0; r.lockedUntil = 0; }
    }

    private static java.util.Map<String, String> parseForm(HttpExchange ex) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        int total = 0;
        InputStream is = ex.getRequestBody();
        while ((len = is.read(buffer)) != -1) {
            total += len;
            if (total > 16 * 1024) break; // auth form bodies are tiny; cap to avoid abuse
            bos.write(buffer, 0, len);
        }
        String body = bos.toString(StandardCharsets.UTF_8);
        java.util.Map<String, String> map = new java.util.HashMap<>();
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8.name());
                String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8.name());
                map.put(k, v);
            }
        }
        return map;
    }
    private static void writeJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] response = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.sendResponseHeaders(code, response.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(response); }
    }

    private static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { exchange.sendResponseHeaders(405, -1); return; }
            java.util.Map<String, String> form = parseForm(exchange);
            String nick = form.getOrDefault("nick", "").trim();
            String password = form.getOrDefault("password", "");
            if (!isValidNick(nick)) {
                writeJson(exchange, 400, "{\"status\":\"error\",\"message\":\"Nick must be 3-16 characters: letters, digits, underscore\"}");
                return;
            }
            if (password.length() < 6 || password.length() > 100) {
                writeJson(exchange, 400, "{\"status\":\"error\",\"message\":\"Password must be at least 6 characters\"}");
                return;
            }
            String key = nick.toLowerCase();
            if (accounts.containsKey(key)) {
                writeJson(exchange, 409, "{\"status\":\"error\",\"message\":\"This nickname is already taken\"}");
                return;
            }
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            Account acc = new Account();
            acc.nick = nick;
            acc.salt = Base64.getEncoder().encodeToString(salt);
            acc.iterations = PBKDF2_ITERATIONS;
            acc.hash = pbkdf2(password, salt, PBKDF2_ITERATIONS);
            acc.created = System.currentTimeMillis();
            accounts.put(key, acc);
            saveAccounts();
            String token = createSession(nick);
            setSessionCookie(exchange, token);
            writeJson(exchange, 200, "{\"status\":\"ok\",\"nick\":\"" + escapeJson(nick) + "\"}");
        }
    }

    private static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) { exchange.sendResponseHeaders(405, -1); return; }
            String ip = clientIp(exchange);
            long wait = rateCheck(ip);
            if (wait > 0) {
                writeJson(exchange, 429, "{\"status\":\"error\",\"message\":\"Too many attempts. Try again in " + wait + "s\"}");
                return;
            }
            java.util.Map<String, String> form = parseForm(exchange);
            String nick = form.getOrDefault("nick", "").trim();
            String password = form.getOrDefault("password", "");
            Account acc = accounts.get(nick.toLowerCase());
            if (acc == null || !verifyPassword(password, acc)) {
                rateFail(ip);
                writeJson(exchange, 401, "{\"status\":\"error\",\"message\":\"Invalid nickname or password\"}");
                return;
            }
            rateReset(ip);
            String token = createSession(acc.nick);
            setSessionCookie(exchange, token);
            writeJson(exchange, 200, "{\"status\":\"ok\",\"nick\":\"" + escapeJson(acc.nick) + "\"}");
        }
    }

    private static class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String token = getCookie(exchange, "mcb_session");
            if (token != null) { sessions.remove(token); saveSessions(); }
            clearSessionCookie(exchange);
            writeJson(exchange, 200, "{\"status\":\"ok\"}");
        }
    }

    private static class MeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String nick = sessionNick(exchange);
            if (nick == null) { writeJson(exchange, 401, "{\"status\":\"unauthorized\"}"); return; }
            writeJson(exchange, 200, "{\"status\":\"ok\",\"nick\":\"" + escapeJson(nick) + "\"}");
        }
    }

    private static class IndexHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            byte[] response = INDEX_HTML.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class NotifySoundHandler implements HttpHandler {
        private static byte[] CACHE = null;
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            if (CACHE == null) {
                CACHE = java.util.Base64.getDecoder().decode(NOTIFY_WAV_B64);
            }
            exchange.getResponseHeaders().set("Content-Type", "audio/wav");
            exchange.getResponseHeaders().set("Cache-Control", "max-age=86400");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, CACHE.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(CACHE);
            }
        }
    }

    private static class StreamHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            
            String query = exchange.getRequestURI().getQuery();
            String nick = "WebPlayer";
            if (query != null && query.contains("nick=")) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=");
                    if (pair.length == 2 && "nick".equals(pair[0])) {
                        nick = URLDecoder.decode(pair[1], StandardCharsets.UTF_8.name());
                        break;
                    }
                }
            }

            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, 0);

            WebSession session = new WebSession(nick, exchange);
            webSessions.add(session);
            clients.add(exchange);

            broadcastToWeb("[Server]", "§a" + nick + " (Web) joined the chat", false);

            // Keep the SSE connection open. The JDK HttpServer closes the exchange
            // as soon as handle() returns, which would abort the chunked stream and
            // force the browser to reconnect every few seconds. Block here until the
            // client disconnects (detected by the heartbeat/broadcast write failing,
            // which removes the session and releases this latch).
            try {
                session.closeLatch.await();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static class LeaveHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String query = exchange.getRequestURI().getQuery();
            String nick = "";
            if (query != null && query.contains("nick=")) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=");
                    if (pair.length == 2 && "nick".equals(pair[0])) {
                        nick = URLDecoder.decode(pair[1], StandardCharsets.UTF_8.name());
                        break;
                    }
                }
            }
            if (!nick.isEmpty()) {
                List<WebSession> toRemove = new ArrayList<>();
                for (WebSession session : webSessions) {
                    if (session.nick.equalsIgnoreCase(nick)) {
                        toRemove.add(session);
                        session.closeLatch.countDown();
                        clients.remove(session.exchange);
                        try {
                            session.exchange.close();
                        } catch (Exception ignored) {}
                    }
                }
                if (!toRemove.isEmpty()) {
                    webSessions.removeAll(toRemove);
                    broadcastToWeb("[Server]", "§c" + nick + " (Web) left the chat", false);
                }
            }
            byte[] response = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class ServerInfoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String motd = McChatBridge.getServerMotd();
            int online = McChatBridge.getOnlineCount() + webSessions.size();
            int max = McChatBridge.getMaxPlayers();
            String json = String.format("{\"motd\":\"%s\",\"online\":%d,\"max\":%d,\"clickerEnabled\":%b,\"allowImageUploads\":%b}",
                    escapeJson(motd), online, max, config.clickerEnabled, config.allowImageUploads);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class IconHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            File file = new File("server-icon.png");
            if (file.exists() && file.isFile()) {
                exchange.getResponseHeaders().set("Content-Type", "image/png");
                exchange.sendResponseHeaders(200, file.length());
                try (InputStream is = new FileInputStream(file);
                     OutputStream os = exchange.getResponseBody()) {
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        os.write(buffer, 0, len);
                    }
                }
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
        }
    }

    private static class PlayersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String json = getOnlinePlayersJson();
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class PanoramaHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            File file = new File("minecraft-panorama.jpg");
            if (file.exists() && file.isFile()) {
                exchange.getResponseHeaders().set("Content-Type", "image/jpeg");
                exchange.sendResponseHeaders(200, file.length());
                try (InputStream is = new FileInputStream(file);
                     OutputStream os = exchange.getResponseBody()) {
                    byte[] buffer = new byte[1024];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        os.write(buffer, 0, len);
                    }
                }
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
        }
    }

    private static class PrivateSendHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // The sender is the authenticated user; a client "from" is ignored.
            String authNick = sessionNick(exchange);
            if (authNick == null) {
                writeJson(exchange, 401, "{\"status\":\"error\",\"message\":\"Not logged in\"}");
                return;
            }

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String from = authNick;
            String to = "";
            String message = "";
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("to".equals(key)) {
                        to = value.trim();
                    } else if ("message".equals(key)) {
                        message = value.trim();
                    }
                }
            }

            if (!message.isEmpty() && !from.isEmpty() && !to.isEmpty()) {
                long time = System.currentTimeMillis();
                synchronized (privateHistory) {
                    privateHistory.add(new PrivateMessage(from, to, message, time));
                }
                savePrivateHistory();

                boolean isWeb = false;
                for (WebSession session : webSessions) {
                    if (session.nick.equalsIgnoreCase(to)) {
                        isWeb = true;
                        break;
                    }
                }
                if (!isWeb) {
                    McChatBridge.sendPrivateToMinecraft(from, to, message);
                }

                String json = String.format("{\"type\":\"private\",\"from\":\"%s\",\"to\":\"%s\",\"text\":\"%s\",\"time\":%d}",
                        escapeJson(from),
                        escapeJson(to),
                        escapeJson(message),
                        time
                );
                String eventData = "data: " + json + "\n\n";
                byte[] bytes = eventData.getBytes(StandardCharsets.UTF_8);

                List<HttpExchange> toRemove = new ArrayList<>();
                for (HttpExchange clientExchange : clients) {
                    try {
                        OutputStream os = clientExchange.getResponseBody();
                        os.write(bytes);
                        os.flush();
                    } catch (IOException e) {
                        toRemove.add(clientExchange);
                    }
                }
                if (!toRemove.isEmpty()) {
                    clients.removeAll(toRemove);
                    for (HttpExchange clientExchange : toRemove) {
                        try {
                            clientExchange.close();
                        } catch (Exception ignored) {}
                    }
                }
            }

            byte[] response = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class PrivateHistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            // Only the logged-in user may read their own private history.
            String user = sessionNick(exchange);
            if (user == null) {
                writeJson(exchange, 401, "{\"status\":\"unauthorized\"}");
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("[");
            if (!user.isEmpty()) {
                synchronized (privateHistory) {
                    int count = 0;
                    for (PrivateMessage msg : privateHistory) {
                        if (user.equalsIgnoreCase(msg.from) || user.equalsIgnoreCase(msg.to)) {
                            if (count > 0) sb.append(",");
                            sb.append(String.format("{\"from\":\"%s\",\"to\":\"%s\",\"text\":\"%s\",\"time\":%d}",
                                    escapeJson(msg.from),
                                    escapeJson(msg.to),
                                    escapeJson(msg.text),
                                    msg.time
                            ));
                            count++;
                        }
                    }
                }
            }
            sb.append("]");

            byte[] response = sb.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class UploadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            if (!config.allowImageUploads) {
                byte[] response = "{\"success\":false,\"error\":\"Image uploads are disabled by administrator.\"}"
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(403, response.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
                return;
            }

            String query = exchange.getRequestURI().getQuery();
            String filename = "upload_" + System.currentTimeMillis() + ".png";
            if (query != null && query.contains("name=")) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=");
                    if (pair.length == 2 && "name".equals(pair[0])) {
                        String orig = URLDecoder.decode(pair[1], StandardCharsets.UTF_8.name());
                        String ext = orig.contains(".") ? orig.substring(orig.lastIndexOf(".")) : ".png";
                        filename = "upload_" + UUID.randomUUID().toString() + ext;
                        break;
                    }
                }
            }

            File uploadsDir = new File("config/mcchatbridge_uploads");
            if (!uploadsDir.exists()) {
                uploadsDir.mkdirs();
            }
            File outFile = new File(uploadsDir, filename);
            try (InputStream is = exchange.getRequestBody();
                 OutputStream os = new FileOutputStream(outFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }

            String json = String.format("{\"url\":\"/uploads/%s\"}", filename);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class ServeUploadsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String path = exchange.getRequestURI().getPath();
            String filename = path.substring(path.lastIndexOf("/") + 1);
            File file = new File("config/mcchatbridge_uploads", filename);
            if (file.exists() && file.isFile()) {
                String contentType = "application/octet-stream";
                if (filename.endsWith(".png")) contentType = "image/png";
                else if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) contentType = "image/jpeg";
                else if (filename.endsWith(".gif")) contentType = "image/gif";

                exchange.getResponseHeaders().set("Content-Type", contentType);
                exchange.sendResponseHeaders(200, file.length());
                try (InputStream is = new FileInputStream(file);
                     OutputStream os = exchange.getResponseBody()) {
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        os.write(buffer, 0, len);
                    }
                }
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
        }
    }

    private static class AvatarUploadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            // Avatar belongs to the logged-in user; the query nick is ignored.
            String nick = sessionNick(exchange);
            if (nick == null) {
                writeJson(exchange, 401, "{\"status\":\"error\",\"message\":\"Not logged in\"}");
                return;
            }
            // Read the upload with a hard size cap to avoid disk-filling uploads.
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (InputStream is = exchange.getRequestBody()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                int total = 0;
                while ((bytesRead = is.read(buffer)) != -1) {
                    total += bytesRead;
                    if (total > MAX_AVATAR_BYTES) {
                        writeJson(exchange, 413, "{\"status\":\"error\",\"message\":\"Image too large (max 2 MB)\"}");
                        return;
                    }
                    bos.write(buffer, 0, bytesRead);
                }
            }
            byte[] data = bos.toByteArray();
            // Validate the REAL file type by magic bytes, not by extension.
            String type = detectImageType(data);
            if (type == null) {
                writeJson(exchange, 400, "{\"status\":\"error\",\"message\":\"Only PNG, JPEG or GIF images are allowed\"}");
                return;
            }
            // nick is the validated account name; sanitize defensively for the filename.
            final String safeNick = nick.replaceAll("[^A-Za-z0-9_]", "");
            if (safeNick.isEmpty()) {
                writeJson(exchange, 400, "{\"status\":\"error\",\"message\":\"Invalid nick\"}");
                return;
            }
            File avatarsDir = new File("config/mcchatbridge_avatars");
            if (!avatarsDir.exists()) avatarsDir.mkdirs();
            File[] oldFiles = avatarsDir.listFiles((dir, name) -> name.toLowerCase().startsWith(safeNick.toLowerCase() + "."));
            if (oldFiles != null) {
                for (File f : oldFiles) f.delete();
            }
            File outFile = new File(avatarsDir, safeNick + ".png");
            try (OutputStream os = new FileOutputStream(outFile)) {
                os.write(data);
            }
            writeJson(exchange, 200, "{\"status\":\"ok\",\"url\":\"/avatar/" + safeNick + "\"}");
        }
    }

    // Detect a real image type from its leading magic bytes (null if unsupported).
    private static String detectImageType(byte[] d) {
        if (d == null || d.length < 4) return null;
        if ((d[0] & 0xFF) == 0x89 && d[1] == 0x50 && d[2] == 0x4E && d[3] == 0x47) return "png";
        if ((d[0] & 0xFF) == 0xFF && (d[1] & 0xFF) == 0xD8 && (d[2] & 0xFF) == 0xFF) return "jpeg";
        if (d[0] == 0x47 && d[1] == 0x49 && d[2] == 0x46 && d[3] == 0x38) return "gif";
        return null;
    }

    private static class AvatarServeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String path = exchange.getRequestURI().getPath();
            String raw = URLDecoder.decode(path.substring(path.lastIndexOf("/") + 1), StandardCharsets.UTF_8.name());
            // Sanitize to prevent path traversal (e.g. "../../something").
            String nick = raw.replaceAll("[^A-Za-z0-9_]", "");
            if (nick.isEmpty()) { exchange.sendResponseHeaders(404, -1); return; }
            File avatarsDir = new File("config/mcchatbridge_avatars");
            File file = new File(avatarsDir, nick + ".png");
            if (file.exists() && file.isFile()) {
                String ctype = "image/png";
                try (InputStream pis = new FileInputStream(file)) {
                    byte[] head = new byte[4];
                    int n = pis.read(head);
                    String t = (n >= 4) ? detectImageType(head) : null;
                    if ("jpeg".equals(t)) ctype = "image/jpeg";
                    else if ("gif".equals(t)) ctype = "image/gif";
                }
                exchange.getResponseHeaders().set("Content-Type", ctype);
                exchange.getResponseHeaders().set("Cache-Control", "no-cache");
                exchange.sendResponseHeaders(200, file.length());
                try (InputStream is = new FileInputStream(file);
                     OutputStream os = exchange.getResponseBody()) {
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = is.read(buffer)) != -1) {
                        os.write(buffer, 0, len);
                    }
                }
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
        }
    }

    public static class WebInventory {
        public java.util.Map<String, Integer> ores = new java.util.concurrent.ConcurrentHashMap<>();

        public int get(String oreId) {
            return ores.getOrDefault(oreId, 0);
        }

        public void set(String oreId, int count) {
            ores.put(oreId, count);
        }

        public void add(String oreId, int count) {
            ores.put(oreId, get(oreId) + count);
        }
    }

    public static class WebFurnace {
        public String sourceItem = "";
        public int sourceCount = 0;
        public String outputItem = "";
        public int outputCount = 0;
        public double cookTimeProgress = 0.0;
        public double cookTimeTotal = 0.0;
        public long lastTickTime = System.currentTimeMillis();
        public boolean isActive = false;

        public synchronized void tick(WebInventory inv) {
            long now = System.currentTimeMillis();
            double dt = (now - lastTickTime) / 1000.0;
            lastTickTime = now;
            
            if (dt <= 0) return;
            
            while (dt > 0) {
                if (sourceCount <= 0 || sourceItem.isEmpty()) {
                    isActive = false;
                    cookTimeProgress = 0.0;
                    cookTimeTotal = 0.0;
                    break;
                }
                
                isActive = true;
                
                if (cookTimeTotal <= 0) {
                    if ("coal".equals(sourceItem)) {
                        cookTimeTotal = 3.0;
                        outputItem = "coal_refined";
                    } else if ("iron".equals(sourceItem)) {
                        cookTimeTotal = 5.0;
                        outputItem = "iron_refined";
                    } else if ("diamond".equals(sourceItem)) {
                        cookTimeTotal = 8.0;
                        outputItem = "diamond_refined";
                    } else {
                        cookTimeTotal = 5.0;
                        outputItem = "";
                    }
                }
                
                if (outputItem.isEmpty()) {
                    isActive = false;
                    cookTimeProgress = 0.0;
                    break;
                }

                double needed = cookTimeTotal - cookTimeProgress;
                double step = Math.min(dt, needed);
                cookTimeProgress += step;
                dt -= step;

                if (cookTimeProgress >= cookTimeTotal) {
                    sourceCount--;
                    outputCount++;
                    cookTimeProgress = 0.0;
                    cookTimeTotal = 0.0;
                    
                    if (sourceCount <= 0) {
                        sourceItem = "";
                    }
                }
            }
        }
    }


    public static class ClickerState {
        String oreType;
        int currentHits;
        int requiredHits;
    }

    private static final java.util.Map<String, WebInventory> inventories = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Map<String, ClickerState> clickerStates = new java.util.concurrent.ConcurrentHashMap<>();
    private static final File CLICKER_FILE = new File("config/mcchatbridge_clicker.txt");
        private static final File FURNACE_FILE = new File("config/mcchatbridge_furnaces.txt");
    private static final java.util.Map<String, WebFurnace> furnaces = new java.util.concurrent.ConcurrentHashMap<>();

    public static ClickerState getClickerState(String nick) {
        return clickerStates.computeIfAbsent(nick.toLowerCase(), k -> generateNextBlock());
    }

    private static ClickerState generateNextBlock() {
        ClickerState state = new ClickerState();
        List<ModConfig.OreConfig> configuredOres = config.ores;
        if (configuredOres == null || configuredOres.isEmpty()) {
            state.oreType = "coal";
            state.requiredHits = 2;
            state.currentHits = 0;
            return state;
        }

        double totalWeight = 0;
        for (ModConfig.OreConfig ore : configuredOres) {
            totalWeight += ore.weight;
        }

        double roll = Math.random() * totalWeight;
        double runningSum = 0;
        ModConfig.OreConfig selectedOre = configuredOres.get(0);
        for (ModConfig.OreConfig ore : configuredOres) {
            runningSum += ore.weight;
            if (roll <= runningSum) {
                selectedOre = ore;
                break;
            }
        }

        state.oreType = selectedOre.id;
        state.requiredHits = selectedOre.hits;
        state.currentHits = 0;
        return state;
    }

    private static void loadClicker() {
        if (!CLICKER_FILE.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(CLICKER_FILE, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\|");
                if (parts.length >= 2) {
                    try {
                        String nick = parts[0].toLowerCase();
                        WebInventory inv = new WebInventory();
                        if (parts[1].contains(":")) {
                            String[] items = parts[1].split(",");
                            for (String item : items) {
                                String[] kv = item.split(":");
                                if (kv.length == 2) {
                                    inv.ores.put(kv[0], Integer.parseInt(kv[1]));
                                }
                            }
                        } else if (parts.length >= 6) {
                            if (parts.length == 6) {
                                inv.ores.put("coal", Integer.parseInt(parts[1]));
                                inv.ores.put("lapis", Integer.parseInt(parts[2]));
                                inv.ores.put("redstone", 0);
                                inv.ores.put("iron", Integer.parseInt(parts[3]));
                                inv.ores.put("diamond", Integer.parseInt(parts[4]));
                                inv.ores.put("netherite", Integer.parseInt(parts[5]));
                            } else {
                                inv.ores.put("coal", Integer.parseInt(parts[1]));
                                inv.ores.put("lapis", Integer.parseInt(parts[2]));
                                inv.ores.put("redstone", Integer.parseInt(parts[3]));
                                inv.ores.put("iron", Integer.parseInt(parts[4]));
                                inv.ores.put("diamond", Integer.parseInt(parts[5]));
                                inv.ores.put("netherite", Integer.parseInt(parts[6]));
                            }
                        }
                        inventories.put(nick, inv);
                    } catch (Exception ignored) {}
                }
            }
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to load clicker data: " + e.getMessage());
        }
    }

    private static synchronized void saveClicker() {
        try {
            File parent = CLICKER_FILE.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(CLICKER_FILE, StandardCharsets.UTF_8))) {
                for (java.util.Map.Entry<String, WebInventory> entry : inventories.entrySet()) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(entry.getKey()).append("|");
                    int i = 0;
                    for (java.util.Map.Entry<String, Integer> oreEntry : entry.getValue().ores.entrySet()) {
                        if (i > 0) sb.append(",");
                        sb.append(oreEntry.getKey()).append(":").append(oreEntry.getValue());
                        i++;
                    }
                    writer.write(sb.toString());
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to save clicker data: " + e.getMessage());
        }
    }

    private static void loadFurnaces() {
        if (!FURNACE_FILE.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(FURNACE_FILE, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\|");
                if (parts.length >= 9) {
                    try {
                        String nick = parts[0].toLowerCase();
                        WebFurnace f = new WebFurnace();
                        f.sourceItem = parts[1];
                        f.sourceCount = Integer.parseInt(parts[2]);
                        f.outputItem = parts[3];
                        f.outputCount = Integer.parseInt(parts[4]);
                        f.cookTimeProgress = Double.parseDouble(parts[5]);
                        f.cookTimeTotal = Double.parseDouble(parts[6]);
                        f.lastTickTime = Long.parseLong(parts[7]);
                        f.isActive = Boolean.parseBoolean(parts[8]);
                        furnaces.put(nick, f);
                    } catch (Exception ignored) {}
                }
            }
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to load furnaces data: " + e.getMessage());
        }
    }

    private static synchronized void saveFurnaces() {
        try {
            File parent = FURNACE_FILE.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(FURNACE_FILE, StandardCharsets.UTF_8))) {
                for (java.util.Map.Entry<String, WebFurnace> entry : furnaces.entrySet()) {
                    WebFurnace f = entry.getValue();
                    String line = String.format("%s|%s|%d|%s|%d|%s|%s|%d|%b",
                        entry.getKey(),
                        f.sourceItem,
                        f.sourceCount,
                        f.outputItem,
                        f.outputCount,
                        String.valueOf(f.cookTimeProgress),
                        String.valueOf(f.cookTimeTotal),
                        f.lastTickTime,
                        f.isActive
                    );
                    writer.write(line);
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            System.err.println("[McChatBridge] Failed to save furnaces data: " + e.getMessage());
        }
    }


    private static boolean transferItem(String nick, String ore, int amount, String toPlayer) {
        if (com.example.mcchatbridge.McChatBridge.server == null) return false;
        net.minecraft.server.level.ServerPlayer player = com.example.mcchatbridge.McChatBridge.server.getPlayerList().getPlayerByName(toPlayer);
        if (player == null) return false;

        String itemId = null;
        if ("coal_refined".equalsIgnoreCase(ore)) {
            itemId = "minecraft:coal";
        } else if ("iron_refined".equalsIgnoreCase(ore)) {
            itemId = "minecraft:iron_ingot";
        } else if ("diamond_refined".equalsIgnoreCase(ore)) {
            itemId = "minecraft:diamond";
        } else {
            for (ModConfig.OreConfig o : config.ores) {
                if (o.id.equalsIgnoreCase(ore)) {
                    itemId = o.itemId;
                    break;
                }
            }
        }
        if (itemId == null) return false;

        final String finalItemId = itemId;

        com.example.mcchatbridge.McChatBridge.server.execute(() -> {
            net.minecraft.world.item.Item item = net.minecraft.core.registries.BuiltInRegistries.ITEM.get(
                net.minecraft.resources.ResourceLocation.parse(finalItemId)
            );
            if (item == null || item == net.minecraft.world.item.Items.AIR) {
                System.err.println("[McChatBridge] Item registry lookup failed for: " + finalItemId);
                return;
            }
            net.minecraft.world.item.ItemStack stack = new net.minecraft.world.item.ItemStack(item, amount);
            // Capture the display name BEFORE adding to the inventory: getInventory().add(stack)
            // mutates the stack (drains its count), so afterwards it can be empty -> "Air".
            String itemName = stack.getHoverName().getString();
            player.getInventory().add(stack);
            if (!stack.isEmpty()) {
                player.drop(stack, false);
            }
            player.sendSystemMessage(net.minecraft.network.chat.Component.literal("§6[Clicker] §b" + nick + " §fsent you §e" + itemName + " §f(" + amount + " pcs)!"));
        });
        return true;
    }

    private static class ClickerStatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            if (!config.clickerEnabled) {
                byte[] response = "{\"success\":false,\"error\":\"The clicker mini-game is disabled by administrator.\"}"
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(403, response.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
                return;
            }

            String query = exchange.getRequestURI().getQuery();
            String nick = "";
            if (query != null && query.contains("nick=")) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=");
                    if (pair.length == 2 && "nick".equals(pair[0])) {
                        nick = URLDecoder.decode(pair[1], StandardCharsets.UTF_8.name()).toLowerCase();
                        break;
                    }
                }
            }

            if (nick.isEmpty()) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            ClickerState state = getClickerState(nick);
            WebInventory inv = inventories.computeIfAbsent(nick, k -> new WebInventory());

            java.util.Map<String, Object> respMap = new java.util.HashMap<>();
            respMap.put("ore", state.oreType);
            respMap.put("hits", state.currentHits);
            respMap.put("maxHits", state.requiredHits);
            respMap.put("inventory", inv.ores);
            respMap.put("ores", config.ores);

            String json = new com.google.gson.Gson().toJson(respMap);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class ClickerClickHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            if (!config.clickerEnabled) {
                byte[] response = "{\"success\":false,\"error\":\"The clicker mini-game is disabled by administrator.\"}"
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(403, response.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
                return;
            }

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String nick = "";
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("nick".equals(key)) {
                        nick = value.trim().toLowerCase();
                    }
                }
            }

            if (nick.isEmpty()) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            ClickerState state = getClickerState(nick);
            WebInventory inv = inventories.computeIfAbsent(nick, k -> new WebInventory());

            state.currentHits++;
            boolean mined = false;
            String reward = "";

            if (state.currentHits >= state.requiredHits) {
                mined = true;
                reward = state.oreType;
                inv.add(reward, 1);
                saveClicker();
        saveFurnaces();

                // Generate new block
                ClickerState nextState = generateNextBlock();
                clickerStates.put(nick, nextState);
                state = nextState;
            }

            java.util.Map<String, Object> respMap = new java.util.HashMap<>();
            respMap.put("ore", state.oreType);
            respMap.put("hits", state.currentHits);
            respMap.put("maxHits", state.requiredHits);
            respMap.put("mined", mined);
            respMap.put("reward", reward);
            respMap.put("inventory", inv.ores);

            String json = new com.google.gson.Gson().toJson(respMap);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class ClickerTransferHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            if (!config.clickerEnabled) {
                byte[] response = "{\"success\":false,\"error\":\"The clicker mini-game is disabled by administrator.\"}"
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.sendResponseHeaders(403, response.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
                return;
            }

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String nick = "";
            String ore = "";
            String to = "";
            int amount = 1;
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("nick".equals(key)) {
                        nick = value.trim();
                    } else if ("ore".equals(key)) {
                        ore = value.trim().toLowerCase();
                    } else if ("to".equals(key)) {
                        to = value.trim();
                    } else if ("amount".equals(key)) {
                        try {
                            amount = Integer.parseInt(value.trim());
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }

            if (amount < 1) amount = 1;

            if (nick.isEmpty() || ore.isEmpty() || to.isEmpty()) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }

            WebInventory inv = inventories.get(nick.toLowerCase());
            boolean success = false;
            String errorMsg = "";

            if (!ore.endsWith("_refined") && !ore.equals("lapis") && !ore.equals("redstone") && !ore.equals("netherite")) {
                errorMsg = "You can only transfer refined ores or direct items (lapis, redstone, netherite)!";
            } else if (inv != null) {
                int count = inv.get(ore);

                if (count >= amount) {
                    // Attempt to give in-game
                    if (transferItem(nick, ore, amount, to)) {
                        // Decrement
                        inv.add(ore, -amount);
                        saveClicker();
        saveFurnaces();
                        success = true;
                    } else {
                        errorMsg = "Player is not online!";
                    }
                } else {
                    errorMsg = "Insufficient resources!";
                }
            } else {
                errorMsg = "Inventory not found!";
            }

            java.util.Map<String, Object> respMap = new java.util.HashMap<>();
            respMap.put("success", success);
            respMap.put("error", errorMsg);
            respMap.put("inventory", inv != null ? inv.ores : new java.util.HashMap<>());

            String json = new com.google.gson.Gson().toJson(respMap);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class ClickerTexturesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/javascript");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            byte[] response = TEXTURES_JS.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    
    private static class ClickerFurnaceStatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String query = exchange.getRequestURI().getQuery();
            String nick = "";
            if (query != null && query.contains("nick=")) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=");
                    if (pair.length == 2 && "nick".equals(pair[0])) {
                        nick = URLDecoder.decode(pair[1], StandardCharsets.UTF_8.name()).trim();
                        break;
                    }
                }
            }

            java.util.Map<String, Object> respMap = new java.util.HashMap<>();
            if (nick.isEmpty()) {
                respMap.put("status", "error");
                respMap.put("message", "Nickname required");
            } else {
                String key = nick.toLowerCase();
                WebInventory inv = inventories.computeIfAbsent(key, k -> new WebInventory());
                WebFurnace f = furnaces.computeIfAbsent(key, k -> {
                    WebFurnace newF = new WebFurnace();
                    newF.lastTickTime = System.currentTimeMillis();
                    return newF;
                });
                
                boolean changed;
                synchronized (f) {
                    int oldSource = f.sourceCount;
                    int oldOutput = f.outputCount;

                    f.tick(inv);

                    changed = (f.sourceCount != oldSource || f.outputCount != oldOutput);

                    respMap.put("status", "ok");
                    respMap.put("sourceItem", f.sourceItem);
                    respMap.put("sourceCount", f.sourceCount);
                    respMap.put("outputItem", f.outputItem);
                    respMap.put("outputCount", f.outputCount);
                    respMap.put("cookProgress", f.cookTimeProgress);
                    respMap.put("cookTotal", f.cookTimeTotal);
                    respMap.put("isActive", f.isActive);
                }

                if (changed) {
                    saveFurnaces();
                }
            }

            String json = new com.google.gson.Gson().toJson(respMap);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class ClickerFurnaceAddHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            
            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String nick = "";
            String item = "";
            int amount = 1;

            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String k = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String v = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("nick".equals(k)) {
                        nick = v.trim();
                    } else if ("item".equals(k)) {
                        item = v.trim();
                    } else if ("amount".equals(k)) {
                        try {
                            amount = Integer.parseInt(v.trim());
                        } catch (Exception ignored) {}
                    }
                }
            }

            java.util.Map<String, Object> respMap = new java.util.HashMap<>();
            if (nick.isEmpty() || item.isEmpty() || amount <= 0) {
                respMap.put("status", "error");
                respMap.put("message", "Invalid parameters");
            } else {
                String key = nick.toLowerCase();
                WebInventory inv = inventories.computeIfAbsent(key, k -> new WebInventory());
                WebFurnace f = furnaces.computeIfAbsent(key, k -> {
                    WebFurnace newF = new WebFurnace();
                    newF.lastTickTime = System.currentTimeMillis();
                    return newF;
                });

                boolean accepted = false;
                final String itemFinal = item;
                final int amountFinal = amount;
                synchronized (f) {
                    f.tick(inv);

                    if (!"coal".equals(itemFinal) && !"iron".equals(itemFinal) && !"diamond".equals(itemFinal)) {
                        respMap.put("status", "error");
                        respMap.put("message", "Only Coal, Iron Ore, and Diamond Ore can be smelted");
                    } else if (inv.get(itemFinal) < amountFinal) {
                        respMap.put("status", "error");
                        respMap.put("message", "Not enough resources");
                    } else if (!f.sourceItem.isEmpty() && !f.sourceItem.equals(itemFinal)) {
                        respMap.put("status", "error");
                        respMap.put("message", "Furnace already has a different item inside");
                    } else {
                        inv.set(itemFinal, inv.get(itemFinal) - amountFinal);

                        f.sourceItem = itemFinal;
                        f.sourceCount += amountFinal;
                        f.lastTickTime = System.currentTimeMillis();
                        f.isActive = true;

                        accepted = true;
                        respMap.put("status", "ok");
                        respMap.put("sourceCount", f.sourceCount);
                    }
                }

                if (accepted) {
                    saveClicker();
                    saveFurnaces();
                }
            }

            String json = new com.google.gson.Gson().toJson(respMap);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class ClickerFurnaceTakeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String nick = "";
            String slot = "";

            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String k = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String v = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("nick".equals(k)) {
                        nick = v.trim();
                    } else if ("slot".equals(k)) {
                        slot = v.trim();
                    }
                }
            }

            java.util.Map<String, Object> respMap = new java.util.HashMap<>();
            if (nick.isEmpty() || slot.isEmpty()) {
                respMap.put("status", "error");
                respMap.put("message", "Invalid parameters");
            } else {
                String key = nick.toLowerCase();
                WebInventory inv = inventories.computeIfAbsent(key, k -> new WebInventory());
                WebFurnace f = furnaces.computeIfAbsent(key, k -> {
                    WebFurnace newF = new WebFurnace();
                    newF.lastTickTime = System.currentTimeMillis();
                    return newF;
                });

                boolean changed = false;
                final String slotFinal = slot;
                synchronized (f) {
                    f.tick(inv);

                    if ("source".equals(slotFinal)) {
                        if (f.sourceCount > 0 && !f.sourceItem.isEmpty()) {
                            inv.add(f.sourceItem, f.sourceCount);
                            f.sourceCount = 0;
                            f.sourceItem = "";
                            f.cookTimeProgress = 0.0;
                            f.cookTimeTotal = 0.0;
                            f.isActive = false;

                            changed = true;
                            respMap.put("status", "ok");
                        } else {
                            respMap.put("status", "error");
                            respMap.put("message", "Input slot is empty");
                        }
                    } else if ("output".equals(slotFinal)) {
                        if (f.outputCount > 0 && !f.outputItem.isEmpty()) {
                            inv.add(f.outputItem, f.outputCount);
                            f.outputCount = 0;
                            f.outputItem = "";

                            changed = true;
                            respMap.put("status", "ok");
                        } else {
                            respMap.put("status", "error");
                            respMap.put("message", "Output slot is empty");
                        }
                    } else {
                        respMap.put("status", "error");
                        respMap.put("message", "Unknown slot");
                    }
                }

                if (changed) {
                    saveClicker();
                    saveFurnaces();
                }
            }

            String json = new com.google.gson.Gson().toJson(respMap);
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }


    private static class HistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("[");
            synchronized (history) {
                for (int i = 0; i < history.size(); i++) {
                    ChatMessage msg = history.get(i);
                    sb.append(String.format("{\"sender\":\"%s\",\"text\":\"%s\",\"time\":%d,\"isWeb\":%b}",
                            escapeJson(msg.sender),
                            escapeJson(msg.text),
                            msg.time,
                            msg.isWeb
                    ));
                    if (i < history.size() - 1) {
                        sb.append(",");
                    }
                }
            }
            sb.append("]");

            byte[] response = sb.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static class SendHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Identity comes from the session, not the client. A client-supplied
            // "nick" is ignored so nobody can post as someone else.
            String nick = sessionNick(exchange);
            if (nick == null) {
                writeJson(exchange, 401, "{\"status\":\"error\",\"message\":\"Not logged in\"}");
                return;
            }

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String message = "";
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("ignored_nick".equals(key)) {
                        // client nick intentionally ignored
                    } else if ("message".equals(key)) {
                        message = value.trim();
                    }
                }
            }

            if (!message.isEmpty() && !nick.isEmpty()) {
                if (nick.length() > 16) {
                    nick = nick.substring(0, 16);
                }
                if (message.length() > 100) {
                    message = message.substring(0, 100);
                }
                
                String host = exchange.getRequestHeaders().getFirst("Host");
                McChatBridge.sendToMinecraft(nick, message, host);
                broadcastToWeb(nick, message, true);
            }

            byte[] response = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response);
            }
        }
    }

    private static final String INDEX_HTML_PART1 = "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n    <meta charset=\"UTF-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no\">\n    <title>Minecraft Chat Bridge</title>\n    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n    <style>\n        @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');\n        :root {\n            --mc-dark-bg: rgba(16, 0, 16, 0.92);\n            --mc-purple-border: #2e0066;\n            --mc-purple-shadow: #1f0033;\n            --mc-gray-btn: #5c5c5c;\n            --mc-btn-hover: #7a7a7a;\n            --mc-btn-active: #3c3c3c;\n            --mc-border-light: #aeaeae;\n            --mc-border-dark: #2e2e2e;\n        }\n        * {\n            box-sizing: border-box;\n            margin: 0;\n            padding: 0;\n            font-family: 'Press Start 2P', monospace;\n            image-rendering: pixelated;\n        }\n        html, body {\n            height: 100%;\n            height: 100dvh;\n            margin: 0;\n            padding: 0;\n        }\n        body {\n            background-color: #141414;\n            display: flex;\n            justify-content: center;\n            align-items: center;\n            color: #ffffff;\n            overflow: hidden;\n        }\n        \n        .panorama-bg {\n            position: fixed;\n            top: -20px;\n            left: -20px;\n            width: calc(100vw + 40px);\n            height: calc(100vh + 40px);\n            background-image: url('/minecraft-panorama.jpg');\n            background-size: auto 110%;\n            background-position: 0 center;\n            background-repeat: repeat-x;\n            filter: blur(12px) brightness(0.55);\n            z-index: -1;\n            animation: panorama-scroll 180s linear infinite;\n        }\n        @keyframes panorama-scroll {\n            from {\n                background-position: 0 center;\n            }\n            to {\n                background-position: -2048px center;\n            }\n        }\n        \n        .chat-container {\n            width: 100%;\n            max-width: 550px;\n            height: calc(100% - 32px);\n            max-height: 750px;\n            background: var(--mc-dark-bg);\n            border: 4px solid var(--mc-purple-border);\n            box-shadow: 0 0 0 4px var(--mc-purple-shadow), 0 20px 40px rgba(0,0,0,0.8);\n            display: flex;\n            flex-direction: column;\n            position: relative;\n            overflow: hidden;\n        }\n        \n        .tabs-bar {\n            display: flex;\n            background: rgba(0, 0, 0, 0.4);\n            border-bottom: 4px solid #5c5c5c;\n            padding: 8px 8px 0 8px;\n            gap: 4px;\n            overflow-x: auto;\n            flex-shrink: 0;\n            z-index: 12;\n        }\n        .tabs-bar::-webkit-scrollbar {\n            height: 4px;\n        }\n        .tabs-bar::-webkit-scrollbar-thumb {\n            background: #5c5c5c;\n        }\n        .tab {\n            background: #3c3c3c;\n            border-top: 3px solid var(--mc-border-light);\n            border-left: 3px solid var(--mc-border-light);\n            border-right: 3px solid var(--mc-border-dark);\n            border-bottom: 3px solid #5c5c5c;\n            padding: 6px 12px;\n            font-size: 9px;\n            color: #aaaaaa;\n            cursor: pointer;\n            position: relative;\n            top: 3px;\n            display: flex;\n            align-items: center;\n            gap: 6px;\n        }\n        .tab.active {\n            background: var(--mc-dark-bg);\n            border-bottom: 3px solid transparent;\n            color: #ffff55;\n            top: 0;\n            padding-bottom: 9px;\n            z-index: 2;\n        }\n        .tab.unread {\n            color: #ff5555;\n            border-top-color: #ff5555;\n            border-left-color: #ff5555;\n        }\n        .tab-close {\n            color: #ff5555;\n            font-weight: bold;\n            cursor: pointer;\n            font-size: 11px;\n        }\n        .tab-close:hover {\n            color: #ffaa00;\n        }\n        \n        .header {\n            flex-shrink: 0;\n            padding: 16px 20px;\n            border-bottom: 4px solid #5c5c5c;\n            display: flex;\n            align-items: center;\n            justify-content: space-between;\n            background: rgba(0,0,0,0.4);\n            z-index: 11;\n        }\n        .server-title-container {\n            display: flex;\n            align-items: center;\n            gap: 12px;\n            min-width: 0;\n        }\n        .server-icon {\n            width: 32px;\n            height: 32px;\n            border: 2px solid var(--mc-border-light);\n            background-color: #000;\n            object-fit: cover;\n            cursor: pointer;\n            transition: transform 0.1s ease;\n        }\n        .server-icon:hover {\n            border-color: #ffff55;\n            transform: scale(1.1);\n        }\n        .header h1 {\n            font-size: 11px;\n            font-weight: normal;\n            text-shadow: 2px 2px 0px #000;\n            color: #ffff55;\n            line-height: 1.4;\n            white-space: nowrap;\n            overflow: hidden;\n            text-overflow: ellipsis;\n        }\n        .header-actions {\n            display: flex;\n            align-items: center;\n            gap: 8px;\n            flex-shrink: 0;\n        }\n        .status {\n            display: flex;\n            align-items: center;\n            font-size: 10px;\n            color: #aaaaaa;\n            background: #000000;\n            border: 2px solid #5c5c5c;\n            padding: 4px 8px;\n            text-shadow: 2px 2px 0px #000;\n        }\n        .status-dot {\n            width: 6px;\n            height: 6px;\n            background: #55ff55;\n            margin-right: 6px;\n            box-shadow: 0 0 4px #55ff55;\n        }\n        .status.connecting .status-dot {\n            background: #ffaa00;\n            box-shadow: 0 0 4px #ffaa00;\n        }\n        .setup-pane {\n            flex-shrink: 0;\n            padding: 12px 20px;\n            display: flex;\n            align-items: center;\n            gap: 12px;\n            border-bottom: 2px solid #5c5c5c;\n            background: rgba(0,0,0,0.2);\n            z-index: 5;\n        }\n        .my-avatar-wrapper {\n            position: relative;\n            cursor: pointer;\n            flex-shrink: 0;\n        }\n        .my-avatar {\n            width: 36px;\n            height: 36px;\n            border: 2px solid var(--mc-border-light);\n            object-fit: cover;\n            image-rendering: pixelated;\n            background-color: #333;\n            transition: border-color 0.15s;\n        }\n        .my-avatar-wrapper:hover .my-avatar {\n            border-color: #ffff55;\n        }\n        .my-avatar-badge {\n            position: absolute;\n            bottom: -2px;\n            right: -2px;\n            background: #5555ff;\n            color: #fff;\n            font-size: 8px;\n            width: 14px;\n            height: 14px;\n            display: flex;\n            align-items: center;\n            justify-content: center;\n            border: 1px solid #000;\n        }\n        .input-field {\n            background: #000000;\n            border: 2px solid #5c5c5c;\n            color: #ffffff;\n            padding: 10px 14px;\n            font-size: 12px;\n            outline: none;\n            text-shadow: 2px 2px 0px #222;\n            border-radius: 0;\n        }\n        .input-field:focus {\n            border-color: #ffffff;\n        }\n        .nick-input {\n            flex: 1;\n            max-width: 200px;\n        }\n        .messages-area {\n            flex: 1;\n            flex-shrink: 1;\n            min-height: 0;\n            overflow-y: auto;\n            padding: 20px;\n            display: flex;\n            flex-direction: column;\n            gap: 8px;\n            background: rgba(0, 0, 0, 0.35);\n        }\n        .messages-area::-webkit-scrollbar {\n            width: 8px;\n        }\n        .messages-area::-webkit-scrollbar-thumb {\n            background: #5c5c5c;\n            border: 2px solid #000;\n        }\n        .msg-row {\n            font-size: 12px;\n            line-height: 1.6;\n            word-break: break-word;\n            text-shadow: 2px 2px 0px #1e1e1e;\n            padding: 6px 10px;\n            background: rgba(255, 255, 255, 0.02);\n            border-left: 3px solid #5555ff;\n        }\n        .msg-row.self-msg {\n            border-left-color: #ffaa00;\n            background: rgba(255, 170, 0, 0.02);\n        }\n        .msg-row.system-msg {\n            border-left-color: #ff5555;\n            background: rgba(255, 85, 85, 0.04);\n            font-style: italic;\n        }\n        .sender-name {\n            text-decoration: none;\n        }\n        .chat-image {\n            max-width: 100%;\n            max-height: 200px;\n            border: 2px solid #5c5c5c;\n            margin-top: 6px;\n            display: block;\n            cursor: zoom-in;\n        }\n        .chat-image:hover {\n            border-color: #ffffff;\n        }\n        .msg-time {\n            color: #777777;\n            margin-right: 8px;\n            font-size: 10px;\n        }\n        .input-pane {\n            flex-shrink: 0;\n            padding: 16px 20px;\n            display: flex;\n            gap: 8px;\n            border-top: 4px solid #5c5c5c;\n            background: rgba(0,0,0,0.4);\n            z-index: 5;\n            position: relative;\n        }\n        .message-input {\n            flex: 1;\n            min-width: 0;\n        }\n        \n        .emoji-picker {\n            position: absolute;\n            bottom: 75px;\n            left: 20px;\n            background: var(--mc-dark-bg);\n            border: 3px solid var(--mc-purple-border);\n            box-shadow: 0 0 0 3px var(--mc-purple-shadow);\n            padding: 8px;\n            display: grid;\n            grid-template-columns: repeat(4, 1fr);\n            gap: 8px;\n            z-index: 100;\n        }\n        .emoji-picker span {\n            font-size: 18px;\n            cursor: pointer;\n            text-align: center;\n            user-select: none;\n        }\n        .emoji-picker span:hover {\n            transform: scale(1.25);\n        }\n        \n        .btn {\n            background: var(--mc-gray-btn);\n            border-top: 2px solid var(--mc-border-light);\n            border-left: 2px solid var(--mc-border-light);\n            border-right: 2px solid var(--mc-border-dark);\n            border-bottom: 2px solid var(--mc-border-dark);\n            color: #e0e0e0;\n            padding: 10px 16px;\n            font-size: 12px;\n            cursor: pointer;\n            outline: none;\n            text-shadow: 2px 2px 0px #000;\n            border-radius: 0;\n            flex-shrink: 0;\n            display: flex;\n            align-items: center;\n            justify-content: center;\n        }\n        .btn:hover {\n            background: var(--mc-btn-hover);\n            color: #ffffa0;\n            border-top: 2px solid #ffffff;\n            border-left: 2px solid #ffffff;\n            border-right: 2px solid #3c3c3c;\n            border-bottom: 2px solid #3c3c3c;\n        }\n        .btn:active {\n            background: var(--mc-btn-active);\n            border-top: 2px solid var(--mc-border-dark);\n            border-left: 2px solid var(--mc-border-dark);\n            border-right: 2px solid var(--mc-border-light);\n            border-bottom: 2px solid var(--mc-border-light);\n            color: #aaaaaa;\n        }\n        \n        .sidebar {\n            position: absolute;\n            top: 68px;\n            right: -260px;\n            width: 260px;\n            height: calc(100% - 68px);\n            background: var(--mc-dark-bg);\n            border-left: 4px solid var(--mc-purple-border);\n            box-shadow: -4px 0px 0px var(--mc-purple-shadow);\n            transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1);\n            z-index: 20;\n            display: flex;\n            flex-direction: column;\n            padding: 20px;\n            gap: 16px;\n        }\n        .sidebar.open {\n            right: 0;\n        }\n        \n        .left-sidebar {\n            left: -260px;\n            right: auto;\n            border-left: none;\n            border-right: 4px solid var(--mc-purple-border);\n            box-shadow: 4px 0px 0px var(--mc-purple-shadow);\n            transition: left 0.3s cubic-bezier(0.16, 1, 0.3, 1);\n        }\n        .left-sidebar.open {\n            left: 0;\n        }\n        \n        .sidebar-header {\n            font-size: 13px;\n            color: #ffff55;\n            text-shadow: 2px 2px 0px #000;\n            border-bottom: 2px solid #5c5c5c;\n            padding-bottom: 10px;\n            font-weight: normal;\n        }\n        .player-list {\n            display: flex;\n            flex-direction: column;\n            gap: 10px;\n            overflow-y: auto;\n            flex: 1;\n        }\n        .player-list::-webkit-scrollbar {\n            width: 6px;\n        }\n        .player-list::-webkit-scrollbar-thumb {\n            background: #5c5c5c;\n            border: 1px solid #000;\n        }\n        .player-row {\n            display: flex;\n            align-items: center;\n            gap: 12px;\n            padding: 8px 10px;\n            background: rgba(0,0,0,0.3);\n            border: 2px solid #5c5c5c;\n        }\n        .player-row.clickable {\n            cursor: pointer;\n        }\n        .player-row.clickable:hover {\n            border-color: #ffffff;\n            background: rgba(255,255,255,0.05);\n        }\n        .player-avatar {\n            width: 24px;\n            height: 24px;\n            border: 2px solid var(--mc-border-light);\n            object-fit: cover;\n            image-rendering: pixelated;\n            background-color: #555;\n        }\n        .player-name {\n            font-size: 11px;\n            text-shadow: 2px 2px 0px #000;\n            color: #ffffff;\n            white-space: nowrap;\n            overflow: hidden;\n            text-overflow: ellipsis;\n        }\n        \n        @media (max-width: 532px) {\n            .chat-container {\n                margin: 0;\n                height: 100%;\n                max-height: 100%;\n                border: none;\n                box-shadow: none;\n            }\n            .sidebar {\n                width: 100%;\n                right: -100%;\n                border-left: none;\n                box-shadow: none;\n            }\n            .sidebar.open {\n                right: 0;\n            }\n            .left-sidebar {\n                width: 100%;\n                left: -100%;\n                border-right: none;\n                box-shadow: none;\n            }\n            .left-sidebar.open {\n                left: 0;\n            }\n        }\n        \n        /* Clicker styles */\n        .clicker-modal {\n            position: absolute;\n            top: 0;\n            left: 0;\n            width: 100%;\n            height: 100%;\n            background: var(--mc-dark-bg);\n            z-index: 30;\n            display: flex;\n            flex-direction: column;\n            padding: 20px;\n            gap: 16px;\n            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);\n            transform: translateY(100%);\n        }\n        .clicker-modal.open {\n            transform: translateY(0);\n        }\n        .clicker-layout {\n            display: flex;\n            flex-direction: column;\n            gap: 16px;\n            flex: 1;\n            overflow-y: auto;\n        }\n        .clicker-layout::-webkit-scrollbar {\n            width: 6px;\n        }\n        .clicker-layout::-webkit-scrollbar-thumb {\n            background: #5c5c5c;\n            border: 1px solid #000;\n        }\n        .clicker-section {\n            background: rgba(0,0,0,0.3);\n            border: 2px solid #5c5c5c;\n            padding: 16px;\n            display: flex;\n            flex-direction: column;\n            align-items: center;\n            gap: 12px;\n            position: relative;\n        }\n        .clicker-block-container {\n            width: 100px;\n            height: 100px;\n            cursor: pointer;\n            position: relative;\n            transition: transform 0.05s ease;\n            user-select: none;\n            -webkit-user-drag: none;\n        }\n        .clicker-block-container:active {\n            transform: scale(0.92);\n        }\n        .clicker-block-img {\n            width: 100%;\n            height: 100%;\n            image-rendering: pixelated;\n        }\n        .clicker-progress-container {\n            width: 100%;\n            background: #555;\n            border: 2px solid #000;\n            height: 16px;\n            position: relative;\n        }\n        .clicker-progress-bar {\n            height: 100%;\n            background: #55ff55;\n            width: 0%;\n            transition: width 0.1s ease;\n        }\n        .clicker-progress-text {\n            position: absolute;\n            top: 0;\n            left: 0;\n            width: 100%;\n            height: 100%;\n            display: flex;\n            align-items: center;\n            justify-content: center;\n            font-size: 8px;\n            color: #fff;\n            text-shadow: 1px 1px 0px #000;\n        }\n        .clicker-inv-grid {\n            display: grid;\n            grid-template-columns: repeat(6, 1fr);\n            gap: 8px;\n            width: 100%;\n        }\n        .clicker-inv-slot {\n            aspect-ratio: 1;\n            background: #8b8b8b;\n            border-top: 2px solid #fff;\n            border-left: 2px solid #fff;\n            border-right: 2px solid #373737;\n            border-bottom: 2px solid #373737;\n            display: flex;\n            flex-direction: column;\n            align-items: center;\n            justify-content: center;\n            position: relative;\n            cursor: pointer;\n            padding: 4px;\n        }\n        .clicker-inv-slot:hover {\n            background: #9c9c9c;\n            border-color: #fff #fff #373737 #373737;\n        }\n        .clicker-inv-slot.selected {\n            border-color: #ffff55 !important;\n            outline: 2px solid #ffff55;\n        }\n        .clicker-slot-icon {\n            width: 32px;\n            height: 32px;\n            image-rendering: pixelated;\n            object-fit: contain;\n        }\n        .clicker-slot-count {\n            position: absolute;\n            bottom: 2px;\n            right: 4px;\n            font-size: 8px;\n            color: #fff;\n            text-shadow: 1px 1px 0px #000;\n        }\n        .floating-hit {\n            position: absolute;\n            color: #ff5555;\n            font-size: 10px;\n            font-weight: bold;\n            pointer-events: none;\n            text-shadow: 1px 1px 0px #000;\n            animation: floatUp 0.6s ease-out forwards;\n            z-index: 10;\n        }\n        @keyframes floatUp {\n            0% { transform: translateY(0) scale(1); opacity: 1; }\n            100% { transform: translateY(-40px) scale(0.8); opacity: 0; }\n        }\n        .transfer-panel {\n            width: 100%;\n            display: flex;\n            flex-direction: column;\n            gap: 8px;\n            background: rgba(0,0,0,0.5);\n            padding: 12px;\n            border: 2px solid #5c5c5c;\n        }\n        .transfer-panel h3 {\n            font-size: 9px;\n            color: #ffff55;\n            margin-bottom: 4px;\n            font-weight: normal;\n        }\n        .select-field {\n            background: #000;\n            border: 2px solid #5c5c5c;\n            color: #fff;\n            padding: 8px;\n            font-size: 9px;\n            outline: none;\n            width: 100%;\n            cursor: pointer;\n            border-radius: 0;\n        }\n        \n        .clicker-tabs {\n            display: flex;\n            gap: 8px;\n            justify-content: center;\n            margin-bottom: 8px;\n            border-bottom: 2px solid #5c5c5c;\n            padding-bottom: 8px;\n        }\n        .clicker-tab {\n            opacity: 0.6;\n        }\n        .clicker-tab.active {\n            opacity: 1;\n            border-color: #ffff55;\n            color: #ffff55;\n        }\n        .furnace-ui {\n            display: flex;\n            align-items: center;\n            justify-content: center;\n            gap: 20px;\n            width: 100%;\n            padding: 12px;\n            background: rgba(0,0,0,0.4);\n            border: 2px solid #5c5c5c;\n        }\n        \n        @media (max-width: 532px) {\n            .clicker-modal {\n                width: 100%;\n                height: 100%;\n            }\n        }\n\n        .auth-overlay {\n            position: fixed;\n            inset: 0;\n            z-index: 1000;\n            display: flex;\n            align-items: center;\n            justify-content: center;\n            background: rgba(0, 0, 0, 0.82);\n            backdrop-filter: blur(4px);\n        }\n        .auth-card {\n            background: var(--mc-dark-bg);\n            border: 4px solid var(--mc-purple-border);\n            box-shadow: 0 0 0 4px #100016, 0 8px 40px rgba(0,0,0,0.7);\n            padding: 22px 20px;\n            width: 320px;\n            max-width: 92vw;\n            display: flex;\n            flex-direction: column;\n            gap: 12px;\n        }\n        .auth-card h2 {\n            text-align: center;\n            font-size: 14px;\n            margin: 0;\n            color: #fff;\n        }\n        .auth-tabs {\n            display: flex;\n            gap: 6px;\n        }\n        .auth-tab {\n            flex: 1;\n            padding: 8px;\n            font-size: 10px;\n            cursor: pointer;\n            background: var(--mc-gray-btn);\n            color: #cfcfcf;\n            border-top: 2px solid var(--mc-border-light);\n            border-left: 2px solid var(--mc-border-light);\n            border-right: 2px solid var(--mc-border-dark);\n            border-bottom: 2px solid var(--mc-border-dark);\n            font-family: inherit;\n        }\n        .auth-tab.active {\n            background: var(--mc-purple-border);\n            color: #fff;\n        }\n        .auth-card .input-field {\n            width: 100%;\n            box-sizing: border-box;\n        }\n        .auth-error {\n            color: #ff6b6b;\n            font-size: 9px;\n            min-height: 11px;\n            text-align: center;\n            line-height: 1.4;\n        }\n        .auth-hint {\n            color: #888;\n            font-size: 8px;\n            text-align: center;\n            line-height: 1.4;\n        }\n\n        /* PC-only controls are hidden on narrow (mobile) screens */\n        @media (max-width: 532px) {\n            .pc-only { display: none !important; }\n        }\n\n        #scroll-bottom-btn {\n            position: absolute;\n            bottom: 88px;\n            right: 22px;\n            width: 40px;\n            height: 40px;\n            border-radius: 0;\n            background: var(--mc-gray-btn);\n            color: #e0e0e0;\n            border-top: 2px solid var(--mc-border-light);\n            border-left: 2px solid var(--mc-border-light);\n            border-right: 2px solid var(--mc-border-dark);\n            border-bottom: 2px solid var(--mc-border-dark);\n            font-family: inherit;\n            font-size: 12px;\n            text-shadow: 2px 2px 0px #000;\n            image-rendering: pixelated;\n            cursor: pointer;\n            outline: none;\n            opacity: 0;\n            pointer-events: none;\n            transition: opacity 0.2s ease;\n            z-index: 6;\n            display: flex;\n            align-items: center;\n            justify-content: center;\n            padding: 0;\n            line-height: 1;\n        }\n        #scroll-bottom-btn.visible {\n            opacity: 0.5;\n            pointer-events: auto;\n        }\n        #scroll-bottom-btn.visible:hover {\n            opacity: 0.95;\n            background: var(--mc-btn-hover);\n            color: #ffffa0;\n            border-top: 2px solid #ffffff;\n            border-left: 2px solid #ffffff;\n            border-right: 2px solid #3c3c3c;\n            border-bottom: 2px solid #3c3c3c;\n        }\n        #scroll-bottom-btn.visible:active {\n            background: var(--mc-btn-active);\n            border-top: 2px solid var(--mc-border-dark);\n            border-left: 2px solid var(--mc-border-dark);\n            border-right: 2px solid var(--mc-border-light);\n            border-bottom: 2px solid var(--mc-border-light);\n            color: #aaaaaa;\n        }\n        #scroll-bottom-btn.blink {\n            animation: scroll-btn-blink 0.7s ease-in-out infinite;\n        }\n        @keyframes scroll-btn-blink {\n            0%, 100% {\n                opacity: 0.5;\n                background: var(--mc-gray-btn);\n                color: #fff;\n                box-shadow: none;\n            }\n            50% {\n                opacity: 1;\n                background: #ffd23f;\n                color: #000;\n                box-shadow: 0 0 14px 3px rgba(255, 210, 63, 0.85);\n            }\n        }\n    </style>\n   <script>\n       function disconnectOld(oldNick) {\n           if (!oldNick) return;\n           fetch('/leave?nick=' + encodeURIComponent(oldNick), { method: 'POST', keepalive: true });\n       }\n       window.addEventListener('beforeunload', () => {\n           const nick = document.getElementById('nick-input').value.trim();\n           disconnectOld(nick);\n       });\n   </script>\n    <script src=\"/clicker/textures.js\"></script>\n</head>\n<body>\n    <div class=\"auth-overlay\" id=\"auth-overlay\" style=\"display:none;\">\n        <div class=\"auth-card\">\n            <h2 id=\"auth-title\">Log in</h2>\n            <div class=\"auth-tabs\">\n                <button type=\"button\" class=\"auth-tab active\" id=\"auth-tab-login\">Log in</button>\n                <button type=\"button\" class=\"auth-tab\" id=\"auth-tab-register\">Register</button>\n            </div>\n            <form id=\"auth-form\" autocomplete=\"on\">\n                <input type=\"text\" id=\"auth-nick\" class=\"input-field\" placeholder=\"Nickname\" maxlength=\"16\" autocomplete=\"username\">\n                <input type=\"password\" id=\"auth-password\" class=\"input-field\" placeholder=\"Password\" maxlength=\"100\" autocomplete=\"current-password\">\n                <input type=\"password\" id=\"auth-password2\" class=\"input-field\" placeholder=\"Confirm password\" maxlength=\"100\" autocomplete=\"new-password\" style=\"display:none;\">\n                <div class=\"auth-error\" id=\"auth-error\"></div>\n                <button type=\"submit\" class=\"btn\" id=\"auth-submit\" style=\"width:100%;\">Log in</button>\n            </form>\n            <div class=\"auth-hint\" id=\"auth-hint\"></div>\n        </div>\n    </div>\n    <div class=\"panorama-bg\"></div>\n    <div class=\"chat-container\">\n        <div class=\"header\">\n            <div class=\"server-title-container\">\n                <img src=\"/server-icon.png\" class=\"server-icon\" id=\"srv-icon\" alt=\"[Icon]\">\n                <h1 id=\"server-name\">A Minecraft Server</h1>\n            </div>\n            <div class=\"header-actions\">\n                <button class=\"btn\" id=\"toggle-sidebar-btn\" style=\"padding: 4px 10px; font-size: 10px;\">Players (0)</button>\n                <div class=\"status\" id=\"status-panel\">\n                    <span class=\"status-dot\"></span>\n                    <span id=\"status-text\">...</span>\n                </div>\n            </div>\n        </div>\n        \n        <!-- Creative Tabs Bar -->\n        <div class=\"tabs-bar\" id=\"tabs-bar\">\n            <div class=\"tab active\" data-target=\"global\" id=\"tab-global\">Chat</div>\n        </div>\n        \n        <div class=\"setup-pane\">\n            <input type=\"file\" id=\"avatar-input\" style=\"display:none;\" accept=\"image/png,image/jpeg,image/gif\">\n            <div class=\"my-avatar-wrapper\" id=\"avatar-wrapper\" title=\"Click to change avatar\">\n                <img class=\"my-avatar\" id=\"my-avatar\" src=\"data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22 fill=%22%23888888%22><path d=%22M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z%22/></svg>\" alt=\"\">\n                <span class=\"my-avatar-badge\">✎</span>\n            </div>\n            <input type=\"text\" class=\"input-field nick-input\" id=\"nick-input\" placeholder=\"Nickname\" maxlength=\"16\">\n            <button class=\"btn\" id=\"open-clicker-btn\" style=\"padding: 10px 14px; font-size: 14px;\" title=\"Clicker Mini-game\">⛏️</button>\n            <select id=\"lang-select\" style=\"padding: 10px 8px; font-size: 10px; cursor: pointer; border-radius: 0; outline: none; margin-left: 4px; background: var(--mc-gray-btn); color: white; border-top: 2px solid var(--mc-border-light); border-left: 2px solid var(--mc-border-light); border-right: 2px solid var(--mc-border-dark); border-bottom: 2px solid var(--mc-border-dark); font-family: inherit;\">\n                <option value=\"en\">EN</option>\n                <option value=\"ru\">RU</option>\n            </select>\n            <input type=\"file\" id=\"panorama-input\" style=\"display:none;\" accept=\"image/png,image/jpeg,image/gif,image/webp\">\n            <button class=\"btn pc-only\" id=\"panorama-btn\" style=\"padding: 10px 12px; font-size: 14px; margin-left: 4px;\" title=\"Change background\">🖼️</button>\n        </div>\n        <div class=\"messages-area\" id=\"messages-area\">\n        </div>\n        <button type=\"button\" id=\"scroll-bottom-btn\" title=\"Scroll to latest\">▼</button>\n        <form class=\"input-pane\" id=\"chat-form\">\n            <input type=\"file\" id=\"file-input\" style=\"display:none;\" accept=\"image/*,image/gif\">\n            <button type=\"button\" class=\"btn\" id=\"attach-btn\" style=\"padding: 10px 14px; font-size: 12px;\" title=\"Attach image\">📎</button>\n            <button type=\"button\" class=\"btn\" id=\"emoji-btn\" style=\"padding: 10px 14px; font-size: 12px;\" title=\"Emojis\">😀</button>\n            \n            <div class=\"emoji-picker\" id=\"emoji-picker\" style=\"display:none;\">\n                <span>😀</span><span>😂</span><span>😊</span><span>😍</span>\n                <span>👍</span><span>👎</span><span>🔥</span><span>💩</span>\n                <span>👏</span><span>🎉</span><span>🚀</span><span>❤️</span>\n                <span>👀</span><span>🌟</span><span>🎮</span><span>🎯</span>\n            </div>\n            \n            <input type=\"text\" class=\"input-field message-input\" id=\"msg-input\" placeholder=\"Write a message...\" autocomplete=\"off\" maxlength=\"100\">\n            <button type=\"submit\" class=\"btn\" id=\"send-btn\">Send</button>\n        </form>\n        \n        <!-- Right players list sidebar -->\n        <div class=\"sidebar\" id=\"sidebar\">\n            <h2 class=\"sidebar-header\" id=\"sidebar-title\">Online Players</h2>\n            <div class=\"player-list\" id=\"player-list\">\n            </div>\n            <button class=\"btn\" id=\"close-sidebar-btn\" style=\"width: 100%;\">Close</button>\n            <button class=\"btn\" id=\"logout-btn\" style=\"width: 100%; margin-top: 8px; background: #7a1f1f;\">Log out</button>\n        </div>\n\n        <!-- Left chats list sidebar -->\n        <div class=\"sidebar left-sidebar\" id=\"chats-sidebar\">\n            <h2 class=\"sidebar-header\" id=\"chats-title\">Direct Messages</h2>\n            <div class=\"player-list\" id=\"chats-list\">\n            </div>\n            <button class=\"btn\" id=\"close-chats-btn\" style=\"width: 100%;\">Close</button>\n        </div>\n        \n        <!-- Clicker Mini-game Modal -->\n        <div class=\"clicker-modal\" id=\"clicker-modal\">\n            <h2 class=\"sidebar-header\" id=\"clicker-title\" style=\"text-align: center; border-bottom: none; padding-bottom: 0;\">Clicker Mine ⛏️</h2>\n            \n            <!-- Clicker Mode Tabs -->\n            <div class=\"clicker-tabs\">\n                <button class=\"btn clicker-tab active\" id=\"clicker-tab-mine\" onclick=\"switchClickerTab('mine')\">Добыча</button>\n                <button class=\"btn clicker-tab\" id=\"clicker-tab-furnace\" onclick=\"switchClickerTab('furnace')\">Плавка</button>\n            </div>\n            \n            <div class=\"clicker-layout\">\n                <!-- Mining Section (Tab 1) -->\n                <div id=\"clicker-tab-content-mine\" class=\"clicker-tab-content\">\n                    <div class=\"clicker-section\">\n                        <div class=\"clicker-block-container\" id=\"clicker-block\">\n                            <img class=\"clicker-block-img\" id=\"clicker-block-img\" src=\"\" alt=\"Block\">\n                        </div>\n                        <div class=\"clicker-progress-container\">\n                            <div class=\"clicker-progress-bar\" id=\"clicker-progress-bar\"></div>\n                            <div class=\"clicker-progress-text\" id=\"clicker-progress-text\">0 / 0</div>\n                        </div>\n                    </div>\n                </div>\n                \n                <!-- Smelting Section (Tab 2) -->\n                <div id=\"clicker-tab-content-furnace\" class=\"clicker-tab-content\" style=\"display: none;\">\n                    <div class=\"clicker-section\" style=\"gap: 16px;\">\n                        <div class=\"furnace-ui\">\n                            <!-- Input Raw Slot -->\n                            <div style=\"display: flex; flex-direction: column; align-items: center; gap: 6px;\">\n                                <span id=\"furnace-ore-label\" style=\"font-size: 8px; color: #aaa;\">Руда</span>\n                                <div class=\"clicker-inv-slot\" id=\"furnace-input-slot\" style=\"width: 56px; height: 56px; cursor: default; border-color: #373737 #fff #fff #373737; position: relative;\">\n                                    <img class=\"clicker-slot-icon\" id=\"furnace-input-icon\" src=\"\" alt=\"\" style=\"display: none; width: 36px; height: 36px;\">\n                                    <span class=\"clicker-slot-count\" id=\"furnace-input-count\" style=\"display: none; font-size: 8px; right: 4px; bottom: 2px;\">0</span>\n                                </div>\n                            </div>\n                            \n                            <!-- Smelting Animation -->\n                            <div style=\"display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px;\">\n                                <!-- Flame -->\n                                <div id=\"furnace-flame\" style=\"width: 28px; height: 28px; background: #555; clip-path: polygon(50% 0%, 100% 30%, 85% 100%, 15% 100%, 0% 30%); position: relative; overflow: hidden;\" title=\"Flame\">\n                                    <div id=\"furnace-flame-inner\" style=\"position: absolute; bottom: 0; left: 0; width: 100%; height: 0%; background: linear-gradient(to top, #ff3300, #ffaa00); transition: height 0.2s;\"></div>\n                                </div>\n                                <!-- Progress Arrow -->\n                                <div style=\"width: 44px; height: 16px; background: #333; border: 2px solid #5c5c5c; position: relative; overflow: hidden;\">\n                                    <div id=\"furnace-progress-arrow\" style=\"width: 0%; height: 100%; background: #55ff55; transition: width 0.1s linear;\"></div>\n                                    <span id=\"furnace-timer-text\" style=\"position: absolute; top: 0; left: 0; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; font-size: 8px; color: #fff; text-shadow: 1px 1px 0px #000;\"></span>\n                                </div>\n                            </div>\n                            \n                            <!-- Output Refined Slot -->\n                            <div style=\"display: flex; flex-direction: column; align-items: center; gap: 6px;\">\n                                <span id=\"furnace-product-label\" style=\"font-size: 8px; color: #aaa;\">Продукт</span>\n                                <div class=\"clicker-inv-slot\" id=\"furnace-output-slot\" style=\"width: 56px; height: 56px; cursor: default; border-color: #373737 #fff #fff #373737; position: relative;\">\n";
    private static final String INDEX_HTML_PART2 = "                                    <img class=\"clicker-slot-icon\" id=\"furnace-output-icon\" src=\"\" alt=\"\" style=\"display: none; width: 36px; height: 36px;\">\n                                    <span class=\"clicker-slot-count\" id=\"furnace-output-count\" style=\"display: none; font-size: 8px; right: 4px; bottom: 2px;\">0</span>\n                                </div>\n                            </div>\n                        </div>\n                        \n                        <!-- Smelting Controls -->\n                        <div id=\"furnace-controls\" style=\"width: 100%; display: none; flex-direction: column; gap: 8px; background: rgba(0,0,0,0.5); padding: 12px; border: 2px solid #5c5c5c;\">\n                            <div style=\"display: flex; align-items: center; gap: 8px; justify-content: center;\">\n                                <span id=\"furnace-qty-label\" style=\"font-size: 8px; color: #aaa;\">Кол-во:</span>\n                                <input type=\"number\" class=\"select-field\" id=\"furnace-amount-input\" value=\"1\" min=\"1\" style=\"width: 80px; padding: 4px; text-align: center;\">\n                                <button type=\"button\" class=\"btn\" id=\"furnace-max-btn\" style=\"padding: 4px 8px; font-size: 8px; margin: 0;\">MAX</button>\n                            </div>\n                            <button type=\"button\" class=\"btn\" id=\"furnace-smelt-btn\" style=\"margin-top: 4px; width: 100%; background: #a87e2e;\">Начать плавку</button>\n                        </div>\n                    </div>\n                </div>\n                \n                <!-- Inventory Section (Always shown below) -->\n                <div class=\"clicker-section\" style=\"gap: 8px; align-items: stretch;\">\n                    <h3 id=\"clicker-stock-title\" style=\"font-size: 9px; color: #aaaaaa; text-align: center;\">Your Stock:</h3>\n                    <div class=\"clicker-inv-grid\" id=\"clicker-inv-grid\">\n                    </div>\n                </div>\n\n                <!-- Transfer Panel (Only shown when refined/direct selected) -->\n                <div class=\"transfer-panel\" id=\"transfer-panel\" style=\"display: none;\">\n                    <h3 id=\"transfer-panel-title\">Transfer <span id=\"transfer-ore-name\" style=\"color: #ffff55;\">ore</span> to player on server:</h3>\n                    <select class=\"select-field\" id=\"transfer-player-select\">\n                        <option value=\"\">Select player...</option>\n                    </select>\n                    <div style=\"display: flex; align-items: center; gap: 8px; margin-top: 4px;\">\n                        <span id=\"transfer-amount-label\" style=\"font-size: 8px; color: #aaa; white-space: nowrap;\">Amount:</span>\n                        <input type=\"number\" class=\"select-field\" id=\"transfer-amount-input\" value=\"1\" min=\"1\" style=\"width: 80px; padding: 4px;\">\n                        <button type=\"button\" class=\"btn\" id=\"transfer-max-btn\" style=\"padding: 4px 8px; font-size: 8px; margin: 0;\">MAX</button>\n                    </div>\n                    <button type=\"button\" class=\"btn\" id=\"transfer-send-btn\" style=\"margin-top: 4px;\">Send resources</button>\n                </div>\n            </div>\n            \n            <button class=\"btn\" id=\"close-clicker-btn\" style=\"width: 100%;\">Back to chat</button>\n        </div>\n        </div>\n    </div>\n    <script>\n        const messagesArea = document.getElementById('messages-area');\n        const scrollBottomBtn = document.getElementById('scroll-bottom-btn');\n\n        // ---- Chat scroll helpers ----\n        function isChatAtBottom() {\n            return (messagesArea.scrollHeight - messagesArea.scrollTop - messagesArea.clientHeight) < 40;\n        }\n        function hideScrollBtn() {\n            scrollBottomBtn.classList.remove('visible');\n            scrollBottomBtn.classList.remove('blink');\n        }\n        function updateScrollBtn() {\n            if (isChatAtBottom()) {\n                hideScrollBtn();\n            } else {\n                scrollBottomBtn.classList.add('visible');\n            }\n        }\n        function flashScrollBtn() {\n            // A new message arrived while the user is reading older history.\n            scrollBottomBtn.classList.add('visible');\n            scrollBottomBtn.classList.add('blink');\n        }\n        function scrollChatToBottom() {\n            messagesArea.scrollTo({ top: messagesArea.scrollHeight, behavior: 'smooth' });\n            hideScrollBtn();\n        }\n        messagesArea.addEventListener('scroll', () => {\n            if (isChatAtBottom()) hideScrollBtn();\n            else scrollBottomBtn.classList.add('visible');\n        });\n        scrollBottomBtn.addEventListener('click', scrollChatToBottom);\n\n        // ---- Custom panorama background (per-browser, stored locally; PC only) ----\n        const panoramaBg = document.querySelector('.panorama-bg');\n        const panoramaBtn = document.getElementById('panorama-btn');\n        const panoramaInput = document.getElementById('panorama-input');\n\n        function applyPanorama(url) {\n            if (url && panoramaBg) panoramaBg.style.backgroundImage = \"url('\" + url + \"')\";\n        }\n        try {\n            const savedPanorama = localStorage.getItem('mc_chat_panorama');\n            if (savedPanorama) applyPanorama(savedPanorama);\n        } catch (e) {}\n\n        if (panoramaBtn) {\n            panoramaBtn.addEventListener('click', () => panoramaInput.click());\n            panoramaInput.addEventListener('change', () => {\n                const file = panoramaInput.files[0];\n                panoramaInput.value = '';\n                if (!file) return;\n                const reader = new FileReader();\n                reader.onload = (ev) => {\n                    const img = new Image();\n                    img.onload = () => {\n                        // Downscale so it comfortably fits in localStorage (it gets blurred anyway).\n                        const maxW = 1920;\n                        const scale = Math.min(1, maxW / img.width);\n                        const cw = Math.max(1, Math.round(img.width * scale));\n                        const ch = Math.max(1, Math.round(img.height * scale));\n                        const canvas = document.createElement('canvas');\n                        canvas.width = cw;\n                        canvas.height = ch;\n                        canvas.getContext('2d').drawImage(img, 0, 0, cw, ch);\n                        let dataUrl;\n                        try {\n                            dataUrl = canvas.toDataURL('image/jpeg', 0.82);\n                        } catch (e) {\n                            dataUrl = ev.target.result;\n                        }\n                        try {\n                            localStorage.setItem('mc_chat_panorama', dataUrl);\n                            applyPanorama(dataUrl);\n                        } catch (e) {\n                            applyPanorama(dataUrl); // apply for this session even if it won't persist\n                            alert(i18n[currentLang].panoramaTooLarge);\n                        }\n                    };\n                    img.onerror = () => alert(i18n[currentLang].errorUploading);\n                    img.src = ev.target.result;\n                };\n                reader.readAsDataURL(file);\n            });\n        }\n\n        const nickInput = document.getElementById('nick-input');\n        const msgInput = document.getElementById('msg-input');\n        const chatForm = document.getElementById('chat-form');\n        const statusPanel = document.getElementById('status-panel');\n        const statusText = document.getElementById('status-text');\n        const serverName = document.getElementById('server-name');\n        const srvIcon = document.getElementById('srv-icon');\n        \n        const sidebar = document.getElementById('sidebar');\n        const toggleSidebarBtn = document.getElementById('toggle-sidebar-btn');\n        const closeSidebarBtn = document.getElementById('close-sidebar-btn');\n        const playerList = document.getElementById('player-list');\n        \n        const chatsSidebar = document.getElementById('chats-sidebar');\n        const chatsList = document.getElementById('chats-list');\n        const closeChatsBtn = document.getElementById('close-chats-btn');\n        \n        const tabsBar = document.getElementById('tabs-bar');\n        const fileInput = document.getElementById('file-input');\n        const attachBtn = document.getElementById('attach-btn');\n        const emojiBtn = document.getElementById('emoji-btn');\n        const emojiPicker = document.getElementById('emoji-picker');\n        const avatarInput = document.getElementById('avatar-input');\n        const avatarWrapper = document.getElementById('avatar-wrapper');\n        const myAvatar = document.getElementById('my-avatar');\n        const langSelect = document.getElementById('lang-select');\n        \n        let activeTab = 'global';\n        let globalMessages = [];\n        let pmMessages = {};\n        \n        const i18n = {\n            en: {\n                players: \"Players\",\n                chat: \"Chat\",\n                clickToChangeAvatar: \"Click to change avatar\",\n                nickname: \"Nickname\",\n                clickerMiniGame: \"Clicker Mini-game\",\n                attachImage: \"Attach image\",\n                emojis: \"Emojis\",\n                writeMessage: \"Write a message...\",\n                send: \"Send\",\n                onlinePlayers: \"Online Players\",\n                close: \"Close\",\n                directMessages: \"Direct Messages\",\n                clickerMine: \"Clicker Mine ⛏️\",\n                mineTab: \"Mine\",\n                smeltTab: \"Smelting\",\n                furnaceOre: \"Ore\",\n                furnaceProduct: \"Product\",\n                furnaceQty: \"Amount:\",\n                startSmelt: \"Start smelting\",\n                yourStock: \"Your Stock:\",\n                transferOre: \"Transfer %ore% to player on server:\",\n                selectPlayer: \"Select player...\",\n                amount: \"Amount:\",\n                sendResources: \"Send resources\",\n                backToChat: \"Back to chat\",\n                connecting: \"Connecting...\",\n                connected: \"Connected\",\n                errorStatus: \"Error\",\n                enterNick: \"Please enter a nickname first\",\n                invalidAmount: \"Please specify a correct amount!\",\n                notEnoughResources: \"Not enough resources in stock!\",\n                transferSuccess: \"Resources successfully sent to player!\",\n                transferError: \"Error\",\n                sending: \"Sending...\",\n                clickToView: \"Click to open image\",\n                writePM: \"Write direct message\",\n                pmWith: \"DM: \",\n                noPlayers: \"No players online\",\n                noChats: \"No direct messages\",\n                errorUploading: \"Upload error\",\n                logIn: \"Log in\",\n                register: \"Register\",\n                passwordPh: \"Password\",\n                confirmPh: \"Confirm password\",\n                logout: \"Log out\",\n                authNickHint: \"3-16 characters: letters, digits, underscore\",\n                passwordsMismatch: \"Passwords do not match\",\n                changeBg: \"Change background\",\n                panoramaTooLarge: \"Image too large to save — it will reset after reload\"\n            },\n            ru: {\n                players: \"Игроки\",\n                chat: \"Чат\",\n                clickToChangeAvatar: \"Нажмите, чтобы сменить аватарку\",\n                nickname: \"Никнейм\",\n                clickerMiniGame: \"Мини-игра Кликер\",\n                attachImage: \"Прикрепить изображение\",\n                emojis: \"Смайлики\",\n                writeMessage: \"Написать сообщение...\",\n                send: \"Отправить\",\n                onlinePlayers: \"Игроки в сети\",\n                close: \"Назад\",\n                directMessages: \"Переписки\",\n                clickerMine: \"Шахта Кликер ⛏️\",\n                mineTab: \"Добыча\",\n                smeltTab: \"Плавка\",\n                furnaceOre: \"Руда\",\n                furnaceProduct: \"Продукт\",\n                furnaceQty: \"Кол-во:\",\n                startSmelt: \"Начать плавку\",\n                yourStock: \"Ваш склад:\",\n                transferOre: \"Передать %ore% игроку на сервере:\",\n                selectPlayer: \"Выберите игрока...\",\n                amount: \"Количество:\",\n                sendResources: \"Отправить ресурсы\",\n                backToChat: \"Назад в чат\",\n                connecting: \"Подключение...\",\n                connected: \"В сети\",\n                errorStatus: \"Ошибка\",\n                enterNick: \"Сначала введите никнейм!\",\n                invalidAmount: \"Укажите корректное количество!\",\n                notEnoughResources: \"Недостаточно ресурсов на складе!\",\n                transferSuccess: \"Ресурсы успешно отправлены игроку!\",\n                transferError: \"Ошибка\",\n                sending: \"Отправка...\",\n                clickToView: \"Нажмите, чтобы открыть\",\n                writePM: \"Написать личное сообщение\",\n                pmWith: \"ЛС: \",\n                noPlayers: \"Никого нет\",\n                noChats: \"Нет переписок\",\n                errorUploading: \"Ошибка загрузки\",\n                logIn: \"Вход\",\n                register: \"Регистрация\",\n                passwordPh: \"Пароль\",\n                confirmPh: \"Повторите пароль\",\n                logout: \"Выйти\",\n                authNickHint: \"3-16 символов: буквы, цифры, _\",\n                passwordsMismatch: \"Пароли не совпадают\",\n                changeBg: \"Сменить фон\",\n                panoramaTooLarge: \"Картинка слишком большая — сбросится после перезагрузки\"\n            }\n        };\n\n        let currentLang = localStorage.getItem('mc_chat_lang') || 'en';\n\n        function updateLanguageUI() {\n            const lang = currentLang;\n            localStorage.setItem('mc_chat_lang', lang);\n            langSelect.value = lang;\n            \n            document.getElementById('tab-global').textContent = i18n[lang].chat;\n            avatarWrapper.title = i18n[lang].clickToChangeAvatar;\n            nickInput.placeholder = i18n[lang].nickname;\n            openClickerBtn.title = i18n[lang].clickerMiniGame;\n            attachBtn.title = i18n[lang].attachImage;\n            emojiBtn.title = i18n[lang].emojis;\n            const panoBtnEl = document.getElementById('panorama-btn');\n            if (panoBtnEl) panoBtnEl.title = i18n[lang].changeBg;\n            msgInput.placeholder = i18n[lang].writeMessage;\n            \n            const sendBtn = document.getElementById('send-btn');\n            if (sendBtn.textContent !== '...' && sendBtn.textContent !== 'Sending...' && sendBtn.textContent !== 'Отправка...') {\n                sendBtn.textContent = i18n[lang].send;\n            }\n            \n            document.getElementById('sidebar-title').textContent = i18n[lang].onlinePlayers;\n            closeSidebarBtn.textContent = i18n[lang].close;\n            document.getElementById('chats-title').textContent = i18n[lang].directMessages;\n            closeChatsBtn.textContent = i18n[lang].close;\n            document.getElementById('clicker-title').textContent = i18n[lang].clickerMine;\n            document.getElementById('clicker-stock-title').textContent = i18n[lang].yourStock;\n            document.getElementById('clicker-tab-mine').textContent = i18n[lang].mineTab;\n            document.getElementById('clicker-tab-furnace').textContent = i18n[lang].smeltTab;\n            document.getElementById('furnace-ore-label').textContent = i18n[lang].furnaceOre;\n            document.getElementById('furnace-product-label').textContent = i18n[lang].furnaceProduct;\n            document.getElementById('furnace-qty-label').textContent = i18n[lang].furnaceQty;\n            document.getElementById('furnace-smelt-btn').textContent = i18n[lang].startSmelt;\n            document.getElementById('logout-btn').textContent = i18n[lang].logout;\n            if (typeof authMode !== 'undefined') {\n                setAuthMode(authMode);\n            }\n            \n            let oreSpan = `<span id=\"transfer-ore-name\" style=\"color: #ffff55;\">${selectedOreSlot ? (serverOresList.find(o => o.id === selectedOreSlot)?.name || selectedOreSlot) : 'ore'}</span>`;\n            document.getElementById('transfer-panel-title').innerHTML = i18n[lang].transferOre.replace('%ore%', oreSpan);\n            \n            document.getElementById('transfer-amount-label').textContent = i18n[lang].amount;\n            transferSendBtn.textContent = i18n[lang].sendResources;\n            closeClickerBtn.textContent = i18n[lang].backToChat;\n            \n            // Image titles\n            document.querySelectorAll('.chat-image').forEach(img => img.title = i18n[lang].clickToView);\n            \n            // Senders title\n            document.querySelectorAll('.sender-name').forEach(s => {\n                if (s.style.cursor === 'pointer') {\n                    s.title = i18n[lang].writePM;\n                }\n            });\n            \n            // Tab titles\n            document.querySelectorAll('.tab').forEach(t => {\n                const target = t.getAttribute('data-target');\n                if (target && target.startsWith('pm-')) {\n                    const cleanNick = target.replace('pm-', '');\n                    t.childNodes[0].nodeValue = `${i18n[lang].pmWith}${cleanNick} `;\n                }\n            });\n            \n            // Status panel text\n            if (statusPanel.className.includes('connecting')) {\n                statusText.textContent = (statusText.textContent === '...' ? '...' : i18n[lang].connecting);\n            } else {\n                statusText.textContent = i18n[lang].connected;\n            }\n            \n            // Re-render select option\n            if (transferPlayerSelect.options.length > 0) {\n                transferPlayerSelect.options[0].textContent = i18n[lang].selectPlayer;\n            }\n            \n            updateToggleSidebarBtnText();\n        }\n\n        function updateToggleSidebarBtnText(online = null, max = null) {\n            if (online !== null && max !== null) {\n                window.lastOnlineCount = online;\n                window.lastMaxPlayers = max;\n            }\n            const o = window.lastOnlineCount !== undefined ? window.lastOnlineCount : 0;\n            const m = window.lastMaxPlayers !== undefined ? window.lastMaxPlayers : 20;\n            toggleSidebarBtn.textContent = `${i18n[currentLang].players} (${o}/${m})`;\n        }\n        \n        // Nick is now bound to the logged-in account (set after /auth/me or login)\n        // and can no longer be edited freely, so no impersonation is possible.\n        nickInput.readOnly = true;\n\n        toggleSidebarBtn.addEventListener('click', () => {\n            sidebar.classList.toggle('open');\n            chatsSidebar.classList.remove('open');\n        });\n        \n        closeSidebarBtn.addEventListener('click', () => {\n            sidebar.classList.remove('open');\n        });\n        \n        srvIcon.addEventListener('click', (e) => {\n            e.stopPropagation();\n            renderChatsList();\n            chatsSidebar.classList.toggle('open');\n            sidebar.classList.remove('open');\n        });\n        \n        closeChatsBtn.addEventListener('click', () => {\n            chatsSidebar.classList.remove('open');\n        });\n        \n        langSelect.addEventListener('change', () => {\n            currentLang = langSelect.value;\n            updateLanguageUI();\n            if (chatsSidebar.classList.contains('open')) renderChatsList();\n            if (sidebar.classList.contains('open')) loadPlayers();\n        });\n        \n        avatarWrapper.addEventListener('click', () => avatarInput.click());\n        avatarInput.addEventListener('change', () => {\n            const file = avatarInput.files[0];\n            if (!file) return;\n            const nick = nickInput.value.trim();\n            if (!nick) { alert(i18n[currentLang].enterNick); return; }\n            fetch('/avatar/upload?nick=' + encodeURIComponent(nick), {\n                method: 'POST',\n                body: file\n            })\n            .then(res => res.json())\n            .then(data => {\n                avatarInput.value = '';\n                if (data && data.status === 'ok') {\n                    myAvatar.src = '/avatar/' + nick + '?t=' + Date.now();\n                    loadPlayers();\n                } else {\n                    alert((data && data.message) ? data.message : i18n[currentLang].errorUploading);\n                }\n            })\n            .catch(err => {\n                avatarInput.value = '';\n                console.error('Avatar upload error', err);\n            });\n        });\n        \n        function loadMyAvatar() {\n            const nick = nickInput.value.trim();\n            if (!nick) return;\n            const testImg = new Image();\n            testImg.onload = () => { myAvatar.src = '/avatar/' + nick + '?t=' + Date.now(); };\n            testImg.onerror = () => {};\n            testImg.src = '/avatar/' + nick + '?t=' + Date.now();\n        }\n        \n        const openClickerBtn = document.getElementById('open-clicker-btn');\n        const closeClickerBtn = document.getElementById('close-clicker-btn');\n        const clickerModal = document.getElementById('clicker-modal');\n        const clickerBlock = document.getElementById('clicker-block');\n        const clickerBlockImg = document.getElementById('clicker-block-img');\n        const clickerProgressBar = document.getElementById('clicker-progress-bar');\n        const clickerProgressText = document.getElementById('clicker-progress-text');\n        \n        const transferPanel = document.getElementById('transfer-panel');\n        const transferOreName = document.getElementById('transfer-ore-name');\n        const transferPlayerSelect = document.getElementById('transfer-player-select');\n        const transferSendBtn = document.getElementById('transfer-send-btn');\n        const transferAmountInput = document.getElementById('transfer-amount-input');\n        const transferMaxBtn = document.getElementById('transfer-max-btn');\n        \n        let clickerInventory = {};\n        let selectedOreSlot = null;\n        let currentOreType = \"\";\n        let currentHits = 0;\n        let maxHits = 0;\n        let serverOresList = [];\n        if (typeof ORE_TEXTURES === 'undefined') { window.ORE_TEXTURES = {}; }\n\n        const ALL_ITEMS = [\n            { id: 'coal', name: 'Raw Coal', isRaw: true, refinedId: 'coal_refined', baseColor: '#707070' },\n            { id: 'iron', name: 'Raw Iron Ore', isRaw: true, refinedId: 'iron_refined', baseColor: '#d8af93' },\n            { id: 'diamond', name: 'Raw Diamond Ore', isRaw: true, refinedId: 'diamond_refined', baseColor: '#55ffff' },\n            { id: 'lapis', name: 'Lapis Lazuli', isRaw: false, baseColor: '#1010a0' },\n            { id: 'redstone', name: 'Redstone Dust', isRaw: false, baseColor: '#ff0000' },\n            { id: 'netherite', name: 'Netherite Block', isRaw: false, baseColor: '#312c36' },\n            { id: 'coal_refined', name: 'Coal', isRaw: false, baseColor: '#707070' },\n            { id: 'iron_refined', name: 'Iron Ingot', isRaw: false, baseColor: '#ffffff' },\n            { id: 'diamond_refined', name: 'Diamond', isRaw: false, baseColor: '#55ffff' }\n        ];\n\n        let activeClickerTab = 'mine'; // 'mine' or 'furnace'\n        let isSmeltingInProgress = false;\n\n        function adjustColor(hex, percent) {\n            let num = parseInt(hex.replace(\"#\",\"\"), 16),\n                amt = Math.round(2.55 * percent),\n                R = (num >> 16) + amt,\n                G = (num >> 8 & 0x00FF) + amt,\n                B = (num & 0x0000FF) + amt;\n            return \"#\" + (0x1000000 + (R<255?R<0?0:R:255)*0x10000 + (G<255?G<0?0:G:255)*0x100 + (B<255?B<0?0:B:255)).toString(16).slice(1);\n        }\n\n        function getOreSvgUrl(oreType, hits, maxHits) {\n            const texture = ORE_TEXTURES[oreType];\n            let crackPath = \"\";\n            const ratio = hits / maxHits;\n            if (ratio >= 0.75) {\n                crackPath = \"M 1 2 L 3 2 L 3 4 L 5 4 L 5 7 M 6 1 L 6 3 L 7 5 L 4 5\";\n            } else if (ratio >= 0.5) {\n                crackPath = \"M 1 2 L 3 2 L 3 4 L 5 4 M 6 1 L 6 3 L 7 5\";\n            } else if (ratio >= 0.25) {\n                crackPath = \"M 1 2 L 3 2 M 6 1 L 6 3\";\n            }\n\n            if (texture) {\n                let svg = `<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\" width=\"100%\" height=\"100%\" style=\"image-rendering:pixelated;\">`;\n                svg += `<image href=\"${texture}\" x=\"0\" y=\"0\" width=\"16\" height=\"16\" style=\"image-rendering:pixelated;\"/>`;\n                if (crackPath) {\n                    svg += `<g transform=\"scale(2)\" stroke=\"black\" stroke-width=\"0.5\" fill=\"none\" opacity=\"0.7\">`;\n                    svg += `<path d=\"${crackPath}\"/>`;\n                    svg += `</g>`;\n                }\n                svg += `</svg>`;\n                return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));\n            }\n\n            // Fallback (e.g. if netherite fails)\n            let svg = `<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 8 8\" width=\"100%\" height=\"100%\" style=\"image-rendering:pixelated;\">`;\n            svg += `<rect x=\"0\" y=\"0\" width=\"8\" height=\"8\" fill=\"#312c36\"/>`;\n            if (crackPath) {\n                svg += `<path d=\"${crackPath}\" stroke=\"black\" stroke-width=\"0.5\" fill=\"none\" opacity=\"0.6\"/>`;\n            }\n            svg += `</svg>`;\n            return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));\n        }\n\n        let furnacePollInterval = null;\n        let lastOutputCount = 0;\n\n        function startFurnacePolling() {\n            if (furnacePollInterval) return;\n            pollFurnaceStatus();\n            furnacePollInterval = setInterval(pollFurnaceStatus, 500);\n        }\n\n        function stopFurnacePolling() {\n            if (furnacePollInterval) {\n                clearInterval(furnacePollInterval);\n                furnacePollInterval = null;\n            }\n        }\n\n        function switchClickerTab(tab) {\n            activeClickerTab = tab;\n            document.getElementById('clicker-tab-mine').classList.toggle('active', tab === 'mine');\n            document.getElementById('clicker-tab-furnace').classList.toggle('active', tab === 'furnace');\n            \n            document.getElementById('clicker-tab-content-mine').style.display = tab === 'mine' ? 'block' : 'none';\n            document.getElementById('clicker-tab-content-furnace').style.display = tab === 'furnace' ? 'block' : 'none';\n            \n            if (tab === 'mine') {\n                stopFurnacePolling();\n                if (selectedOreSlot) {\n                    const itemInfo = ALL_ITEMS.find(item => item.id === selectedOreSlot);\n                    if (itemInfo && !itemInfo.isRaw) {\n                        transferPanel.style.display = 'flex';\n                    } else {\n                        transferPanel.style.display = 'none';\n                    }\n                } else {\n                    transferPanel.style.display = 'none';\n                }\n            } else {\n                transferPanel.style.display = 'none';\n                startFurnacePolling();\n                if (selectedOreSlot) {\n                    const itemInfo = ALL_ITEMS.find(item => item.id === selectedOreSlot);\n                    if (itemInfo && itemInfo.isRaw) {\n                        updateFurnaceInput(selectedOreSlot);\n                    } else {\n                        clearFurnaceUI();\n                    }\n                } else {\n                    clearFurnaceUI();\n                }\n            }\n        }\n\n        function updateFurnaceInput(oreId) {\n            const itemInfo = ALL_ITEMS.find(item => item.id === oreId);\n            if (!itemInfo) return;\n            const count = clickerInventory[oreId] || 0;\n            \n            const inputIcon = document.getElementById('furnace-input-icon');\n            const inputCount = document.getElementById('furnace-input-count');\n            let texName = oreId + '_ore';\n            \n            inputIcon.src = ORE_TEXTURES[texName] || ORE_TEXTURES[oreId];\n            inputIcon.style.display = 'block';\n            \n            inputCount.textContent = count;\n            inputCount.style.display = 'block';\n            \n            const outputIcon = document.getElementById('furnace-output-icon');\n            outputIcon.src = ORE_TEXTURES[itemInfo.refinedId] || ORE_TEXTURES[oreId];\n            outputIcon.style.display = 'block';\n            outputIcon.style.opacity = '0.35';\n            outputIcon.style.filter = 'grayscale(100%)';\n            \n            const amountInput = document.getElementById('furnace-amount-input');\n            amountInput.value = 1;\n            amountInput.max = count;\n            \n            document.getElementById('furnace-controls').style.display = 'flex';\n        }\n\n        function clearFurnaceUI() {\n            document.getElementById('furnace-input-icon').style.display = 'none';\n            document.getElementById('furnace-input-count').style.display = 'none';\n            document.getElementById('furnace-output-icon').style.display = 'none';\n            document.getElementById('furnace-controls').style.display = 'none';\n            document.getElementById('furnace-timer-text').textContent = '';\n            document.getElementById('furnace-progress-arrow').style.width = '0%';\n            document.getElementById('furnace-flame-inner').style.height = '0%';\n        }\n\n        function startSmelting() {\n            if (!selectedOreSlot) return;\n            const itemInfo = ALL_ITEMS.find(item => item.id === selectedOreSlot);\n            if (!itemInfo || !itemInfo.isRaw) return;\n            \n            const amountInput = document.getElementById('furnace-amount-input');\n            const amount = parseInt(amountInput.value) || 1;\n            const maxAvailable = clickerInventory[selectedOreSlot] || 0;\n            if (amount < 1 || amount > maxAvailable) {\n                alert(i18n[currentLang].invalidAmount || \"Invalid amount\");\n                return;\n            }\n            \n            const nick = nickInput.value.trim();\n            if (!nick) return;\n            \n            const params = new URLSearchParams();\n            params.append('nick', nick);\n            params.append('item', selectedOreSlot);\n            params.append('amount', amount);\n            \n            fetch('/clicker/furnace/add', {\n                method: 'POST',\n                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n                body: params\n            })\n            .then(res => res.json())\n            .then(data => {\n                if (data.status === 'ok') {\n                    amountInput.value = 1;\n                    loadClickerStatus();\n                    pollFurnaceStatus();\n                } else {\n                    alert(data.message);\n                }\n            })\n            .catch(err => console.error('Error adding to furnace', err));\n        }\n\n        function pollFurnaceStatus() {\n            const nick = nickInput.value.trim();\n            if (!nick) return;\n            \n            fetch('/clicker/furnace/status?nick=' + encodeURIComponent(nick))\n                .then(res => res.json())\n                .then(data => {\n                    if (data.status !== 'ok') return;\n                    \n                    const inputSlot = document.getElementById('furnace-input-slot');\n                    const inputIcon = document.getElementById('furnace-input-icon');\n                    const inputCount = document.getElementById('furnace-input-count');\n                    \n                    const outputSlot = document.getElementById('furnace-output-slot');\n                    const outputIcon = document.getElementById('furnace-output-icon');\n                    const outputCount = document.getElementById('furnace-output-count');\n                    \n                    const flameInner = document.getElementById('furnace-flame-inner');\n                    const progressArrow = document.getElementById('furnace-progress-arrow');\n                    const timerText = document.getElementById('furnace-timer-text');\n                    \n                    if (data.sourceCount > 0 && data.sourceItem) {\n                        let texName = data.sourceItem;\n                        if (data.sourceItem === 'coal') texName = 'coal_ore';\n                        else if (data.sourceItem === 'iron') texName = 'iron_ore';\n                        else if (data.sourceItem === 'diamond') texName = 'diamond_ore';\n                        \n                        inputIcon.src = ORE_TEXTURES[texName] || ORE_TEXTURES[data.sourceItem] || getOreSvgUrl(texName, 0, 1);\n                        inputIcon.style.display = 'block';\n                        inputCount.textContent = data.sourceCount;\n                        inputCount.style.display = 'block';\n                        \n                        inputSlot.style.cursor = 'pointer';\n                        inputSlot.title = currentLang === 'ru' ? 'Забрать сырье' : 'Take back raw items';\n                    } else {\n                        inputIcon.style.display = 'none';\n                        inputCount.style.display = 'none';\n                        inputSlot.style.cursor = 'default';\n                        inputSlot.title = '';\n                    }\n                    \n                    if (data.outputCount > 0 && data.outputItem) {\n                        outputIcon.src = ORE_TEXTURES[data.outputItem] || getOreSvgUrl(data.outputItem, 0, 1);\n                        outputIcon.style.display = 'block';\n                        outputIcon.style.opacity = '1.0';\n                        outputIcon.style.filter = 'none';\n                        outputCount.textContent = data.outputCount;\n                        outputCount.style.display = 'block';\n                        \n                        outputSlot.style.cursor = 'pointer';\n                        outputSlot.title = currentLang === 'ru' ? 'Забрать продукт' : 'Collect smelted items';\n                        \n                        if (data.outputCount > lastOutputCount) {\n                            playNotificationSound();\n                            loadClickerStatus();\n                        }\n                        lastOutputCount = data.outputCount;\n                    } else {\n                        lastOutputCount = 0;\n                        if (data.isActive && data.outputItem) {\n                            outputIcon.src = ORE_TEXTURES[data.outputItem] || getOreSvgUrl(data.outputItem, 0, 1);\n                            outputIcon.style.display = 'block';\n                            outputIcon.style.opacity = '0.35';\n                            outputIcon.style.filter = 'grayscale(100%)';\n                            outputCount.style.display = 'none';\n                            outputSlot.style.cursor = 'default';\n                            outputSlot.title = '';\n                        } else {\n                            outputIcon.style.display = 'none';\n                            outputCount.style.display = 'none';\n                            outputSlot.style.cursor = 'default';\n                            outputSlot.title = '';\n                        }\n                    }\n                    \n                    if (data.isActive) {\n                        const flameHeight = 70 + Math.floor(Math.random() * 31);\n                        flameInner.style.height = flameHeight + '%';\n                        \n                        if (data.cookTotal > 0) {\n                            const percent = Math.min(100, Math.floor((data.cookProgress / data.cookTotal) * 100));\n                            progressArrow.style.width = percent + '%';\n                            const remaining = Math.max(0, data.cookTotal - data.cookProgress);\n";
    private static final String INDEX_HTML_PART3 = "                            timerText.textContent = Math.ceil(remaining) + 's';\n                        } else {\n                            progressArrow.style.width = '0%';\n                            timerText.textContent = '';\n                        }\n                    } else {\n                        flameInner.style.height = '0%';\n                        progressArrow.style.width = '0%';\n                        timerText.textContent = '';\n                    }\n                })\n                .catch(err => console.error(\"Error polling furnace:\", err));\n        }\n\n        function takeFurnaceSlot(slotName) {\n            const nick = nickInput.value.trim();\n            if (!nick) return;\n            \n            const params = new URLSearchParams();\n            params.append('nick', nick);\n            params.append('slot', slotName);\n            \n            fetch('/clicker/furnace/take', {\n                method: 'POST',\n                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n                body: params\n            })\n            .then(res => res.json())\n            .then(data => {\n                if (data.status === 'ok') {\n                    loadClickerStatus();\n                    pollFurnaceStatus();\n                } else {\n                    alert(data.message);\n                }\n            })\n            .catch(err => console.error(\"Error taking items from slot:\", err));\n        }\n\n        function rebuildInventoryGrid() {\n            const grid = document.getElementById('clicker-inv-grid');\n            grid.innerHTML = '';\n            ALL_ITEMS.forEach(item => {\n                const slot = document.createElement('div');\n                slot.className = 'clicker-inv-slot';\n                slot.setAttribute('data-ore', item.id);\n                slot.id = 'slot-' + item.id;\n                slot.title = item.name;\n                if (selectedOreSlot === item.id) {\n                    slot.classList.add('selected');\n                }\n                slot.addEventListener('click', () => selectOreSlot(item.id));\n                \n                const img = document.createElement('img');\n                img.className = 'clicker-slot-icon';\n                img.id = 'icon-' + item.id;\n                \n                let texName = item.id;\n                if (item.id === 'coal') texName = 'coal_ore';\n                else if (item.id === 'iron') texName = 'iron_ore';\n                else if (item.id === 'diamond') texName = 'diamond_ore';\n                \n                img.src = ORE_TEXTURES[texName] || ORE_TEXTURES[item.id] || getOreSvgUrl(texName, 0, 1);\n                img.alt = item.name;\n                \n                const countSpan = document.createElement('span');\n                countSpan.className = 'clicker-slot-count';\n                countSpan.id = 'count-' + item.id;\n                countSpan.textContent = clickerInventory[item.id] || 0;\n                \n                const count = clickerInventory[item.id] || 0;\n                if (count === 0) {\n                    img.style.opacity = '0.3';\n                    img.style.filter = 'grayscale(100%)';\n                }\n                \n                slot.appendChild(img);\n                slot.appendChild(countSpan);\n                grid.appendChild(slot);\n            });\n        }\n\n        function loadClickerStatus() {\n            const nick = nickInput.value.trim();\n            if (!nick) return;\n            fetch('/clicker/status?nick=' + encodeURIComponent(nick))\n                .then(res => res.json())\n                .then(data => {\n                    currentOreType = data.ore;\n                    currentHits = data.hits;\n                    maxHits = data.maxHits;\n                    clickerInventory = data.inventory;\n                    rebuildInventoryGrid();\n                    updateClickerUI();\n                })\n                .catch(err => console.error('Error loading clicker status', err));\n        }\n\n        function updateClickerUI() {\n            let texName = currentOreType;\n            if (currentOreType === 'coal') texName = 'coal_ore';\n            else if (currentOreType === 'iron') texName = 'iron_ore';\n            else if (currentOreType === 'diamond') texName = 'diamond_ore';\n            else if (currentOreType === 'lapis') texName = 'lapis_ore';\n            else if (currentOreType === 'redstone') texName = 'redstone_ore';\n            \n            clickerBlockImg.src = getOreSvgUrl(texName, currentHits, maxHits);\n            \n            const percent = Math.min(100, Math.floor((currentHits / maxHits) * 100));\n            clickerProgressBar.style.width = percent + '%';\n            clickerProgressText.textContent = `${currentHits} / ${maxHits}`;\n            \n            ALL_ITEMS.forEach(item => {\n                const countSpan = document.getElementById('count-' + item.id);\n                if (countSpan) {\n                    countSpan.textContent = clickerInventory[item.id] || 0;\n                }\n                const img = document.getElementById('icon-' + item.id);\n                if (img) {\n                    const count = clickerInventory[item.id] || 0;\n                    if (count === 0) {\n                        img.style.opacity = '0.3';\n                        img.style.filter = 'grayscale(100%)';\n                    } else {\n                        img.style.opacity = '1.0';\n                        img.style.filter = 'none';\n                    }\n                }\n            });\n            \n            if (selectedOreSlot) {\n                const count = clickerInventory[selectedOreSlot] || 0;\n                if (count <= 0) {\n                    transferPanel.style.display = 'none';\n                    document.querySelectorAll('.clicker-inv-slot').forEach(s => s.classList.remove('selected'));\n                    selectedOreSlot = null;\n                } else {\n                    const itemInfo = ALL_ITEMS.find(item => item.id === selectedOreSlot);\n                    if (itemInfo && itemInfo.isRaw && activeClickerTab === 'furnace') {\n                        updateFurnaceInput(selectedOreSlot);\n                    }\n                }\n            }\n        }\n\n        function clickBlock(e) {\n            const nick = nickInput.value.trim();\n            if (!nick) return;\n            \n            const rect = clickerBlock.getBoundingClientRect();\n            const x = e.clientX - rect.left;\n            const y = e.clientY - rect.top;\n            \n            const floater = document.createElement('span');\n            floater.className = 'floating-hit';\n            floater.textContent = '-1';\n            floater.style.left = x + 'px';\n            floater.style.top = y + 'px';\n            clickerBlock.appendChild(floater);\n            setTimeout(() => floater.remove(), 600);\n            \n            const params = new URLSearchParams();\n            params.append('nick', nick);\n            \n            fetch('/clicker/click', {\n                method: 'POST',\n                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n                body: params\n            })\n            .then(res => res.json())\n            .then(data => {\n                currentOreType = data.ore;\n                currentHits = data.hits;\n                maxHits = data.maxHits;\n                clickerInventory = data.inventory;\n                updateClickerUI();\n            })\n            .catch(err => console.error('Error clicking block', err));\n        }\n\n        function selectOreSlot(ore) {\n            if (isSmeltingInProgress) return; // Ignore selection during smelting\n            const count = clickerInventory[ore] || 0;\n            if (count <= 0) {\n                document.querySelectorAll('.clicker-inv-slot').forEach(s => s.classList.remove('selected'));\n                selectedOreSlot = null;\n                transferPanel.style.display = 'none';\n                clearFurnaceUI();\n                return;\n            }\n            \n            document.querySelectorAll('.clicker-inv-slot').forEach(s => {\n                if (s.getAttribute('data-ore') === ore) {\n                    s.classList.add('selected');\n                } else {\n                    s.classList.remove('selected');\n                }\n            });\n            \n            selectedOreSlot = ore;\n            const itemInfo = ALL_ITEMS.find(item => item.id === ore);\n            showActionPanelForItem(itemInfo);\n        }\n\n        function showActionPanelForItem(itemInfo) {\n            if (!itemInfo) return;\n            const count = clickerInventory[itemInfo.id] || 0;\n            \n            if (itemInfo.isRaw) {\n                switchClickerTab('furnace');\n                updateFurnaceInput(itemInfo.id);\n                transferPanel.style.display = 'none';\n            } else {\n                switchClickerTab('mine');\n                \n                transferOreName.textContent = itemInfo.name;\n                transferAmountInput.value = 1;\n                transferAmountInput.max = count;\n                transferPanel.style.display = 'flex';\n                \n                fetch('/players')\n                    .then(res => res.json())\n                    .then(data => {\n                        transferPlayerSelect.innerHTML = `<option value=\"\">${i18n[currentLang].selectPlayer}</option>`;\n                        data.forEach(p => {\n                            if (!p.isWeb) {\n                                const opt = document.createElement('option');\n                                opt.value = p.name;\n                                opt.textContent = p.name;\n                                transferPlayerSelect.appendChild(opt);\n                            }\n                        });\n                    });\n            }\n        }\n\n        function transferOre() {\n            const nick = nickInput.value.trim();\n            const toPlayer = transferPlayerSelect.value;\n            if (!nick || !selectedOreSlot || !toPlayer) return;\n            \n            const amount = parseInt(transferAmountInput.value) || 1;\n            const maxAvailable = clickerInventory[selectedOreSlot] || 0;\n            if (amount < 1) {\n                alert(i18n[currentLang].invalidAmount);\n                return;\n            }\n            if (amount > maxAvailable) {\n                alert(i18n[currentLang].notEnoughResources);\n                return;\n            }\n            \n            const params = new URLSearchParams();\n            params.append('nick', nick);\n            params.append('ore', selectedOreSlot);\n            params.append('to', toPlayer);\n            params.append('amount', amount);\n            \n            fetch('/clicker/transfer', {\n                method: 'POST',\n                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n                body: params\n            })\n            .then(res => res.json())\n            .then(data => {\n                clickerInventory = data.inventory;\n                if (data.success) {\n                    alert(i18n[currentLang].transferSuccess);\n                } else {\n                    alert(i18n[currentLang].transferError + ': ' + data.error);\n                }\n                updateClickerUI();\n            })\n            .catch(err => console.error('Error transferring ore', err));\n        }\n\n        // Attach furnace event listeners during layout bindings\n        setTimeout(() => {\n            const smeltBtn = document.getElementById('furnace-smelt-btn');\n            const maxBtn = document.getElementById('furnace-max-btn');\n            if (smeltBtn) smeltBtn.addEventListener('click', startSmelting);\n            const inputSlot = document.getElementById('furnace-input-slot');\n            const outputSlot = document.getElementById('furnace-output-slot');\n            if (inputSlot) inputSlot.addEventListener('click', () => takeFurnaceSlot('source'));\n            if (outputSlot) outputSlot.addEventListener('click', () => takeFurnaceSlot('output'));\n            if (maxBtn) {\n                maxBtn.addEventListener('click', () => {\n                    if (selectedOreSlot) {\n                        document.getElementById('furnace-amount-input').value = clickerInventory[selectedOreSlot] || 1;\n                    }\n                });\n            }\n        }, 500);\n\n        let notifyAudio = null;\n        function playNotificationSound() {\n            try {\n                if (!notifyAudio) {\n                    notifyAudio = new Audio('/notify.wav');\n                    notifyAudio.volume = 0.5;\n                }\n                notifyAudio.currentTime = 0;\n                const p = notifyAudio.play();\n                if (p && typeof p.catch === 'function') p.catch(() => playBeepFallback());\n            } catch (e) {\n                playBeepFallback();\n            }\n        }\n\n        function playBeepFallback() {\n            try {\n                const ctx = new (window.AudioContext || window.webkitAudioContext)();\n                const osc = ctx.createOscillator();\n                const gain = ctx.createGain();\n\n                osc.connect(gain);\n                gain.connect(ctx.destination);\n\n                osc.type = \"sine\";\n\n                osc.frequency.setValueAtTime(1318.51, ctx.currentTime);\n                osc.frequency.setValueAtTime(1567.98, ctx.currentTime + 0.08);\n\n                gain.gain.setValueAtTime(0.08, ctx.currentTime);\n                gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);\n\n                osc.start();\n                osc.stop(ctx.currentTime + 0.4);\n            } catch (e) {\n                console.error(\"Audio playback error:\", e);\n            }\n        }\n\nfunction sendMessage(text) {\n\nconst nick = nickInput.value.trim();\n\nif (!text || !nick) return;\n\n\n\nif (activeTab === 'global') {\n\nconst params = new URLSearchParams();\n\nparams.append('nick', nick);\n\nparams.append('message', text);\n\nfetch('/send', {\n\nmethod: 'POST',\n\nheaders: {\n\n'Content-Type': 'application/x-www-form-urlencoded'\n\n},\n\nbody: params\n\n}).catch(err => console.error(\"Error sending message\", err));\n\n} else {\n\nconst other = activeTab.replace('pm-', '');\n\nconst params = new URLSearchParams();\n\nparams.append('from', nick);\n\nparams.append('to', other);\n\nparams.append('message', text);\n\nfetch('/private/send', {\n\nmethod: 'POST',\n\nheaders: {\n\n'Content-Type': 'application/x-www-form-urlencoded'\n\n},\n\nbody: params\n\n}).catch(err => console.error(\"Error sending PM\", err));\n\n}\n\n}\n\n\nfunction parseMinecraftColors(text) {\n\nif (!text) return \"\";\n\nconst colorMap = {\n\n'0': '#000000', '1': '#0000aa', '2': '#00aa00', '3': '#00aaaa',\n\n'4': '#aa0000', '5': '#aa00aa', '6': '#ffaa00', '7': '#aaaaaa',\n\n'8': '#555555', '9': '#5555ff', 'a': '#55ff55', 'b': '#55ffff',\n\n'c': '#ff5555', 'd': '#ff55ff', 'e': '#ffff55', 'f': '#ffffff'\n\n};\n\nlet html = \"\";\n\nlet bold = false;\n\nlet italic = false;\n\nlet color = null;\n\n\n\nfor (let i = 0; i < text.length; i++) {\n\nif (text[i] === '§' && i + 1 < text.length) {\n\nlet code = text[i+1].toLowerCase();\n\ni++; \n\nif (colorMap[code] !== undefined) {\n\ncolor = colorMap[code];\n\n} else if (code === 'l') {\n\nbold = true;\n\n} else if (code === 'o') {\n\nitalic = true;\n\n} else if (code === 'r') {\n\ncolor = null;\n\nbold = false;\n\nitalic = false;\n\n}\n\ncontinue;\n\n}\n\n\n\nlet style = \"\";\n\nif (color) style += `color:${color};`;\n\nif (bold) style += `font-weight:bold;`;\n\nif (italic) style += `font-style:italic;`;\n\n\n\nlet char = text[i];\n\nif (char === ' ') char = '&nbsp;';\n\nelse if (char === '<') char = '&lt;';\n\nelse if (char === '>') char = '&gt;';\n\n\n\nif (style) {\n\nhtml += `<span style=\"${style}\">${char}</span>`;\n\n} else {\n\nhtml += char;\n\n}\n\n}\n\nreturn html;\n\n}\n\n\nfunction formatTime(timestamp) {\n\nconst date = new Date(timestamp);\n\nconst h = String(date.getHours()).padStart(2, '0');\n\nconst m = String(date.getMinutes()).padStart(2, '0');\n\nreturn `${h}:${m}`;\n\n}\n\n\nfunction formatText(text) {\n\nif (text.includes('[img]') && text.includes('[/img]')) {\n\nconst url = text.substring(text.indexOf('[img]') + 5, text.indexOf('[/img]'));\n\nreturn `<img src=\"${url}\" class=\"chat-image\" onclick=\"window.open('${url}', '_blank')\" title=\"${i18n[currentLang].clickToView}\">`;\n\n}\n\nreturn parseMinecraftColors(text);\n\n}\n\n\nfunction appendMessageToDOM(sender, text, time, isSelf, isWeb) {\n\nconst msgDiv = document.createElement('div');\n\n\n\nif (sender === '[Server]') {\n\nmsgDiv.className = 'msg-row system-msg';\n\n} else {\n\nmsgDiv.className = `msg-row ${isSelf ? 'self-msg' : ''}`;\n\n}\n\n\n\nconst timeSpan = document.createElement('span');\n\ntimeSpan.className = 'msg-time';\n\ntimeSpan.textContent = `[${formatTime(time)}]`;\n\n\n\nconst contentSpan = document.createElement('span');\n\nconst formattedSender = parseMinecraftColors(sender);\n\nconst formattedText = formatText(text);\n\n\n\nif (sender === '[Server]') {\n\ncontentSpan.innerHTML = formattedText;\n\n} else if (isWeb) {\n\ncontentSpan.innerHTML = `&lt;<span class=\"sender-name\" style=\"cursor:pointer;\" onclick=\"openPrivateChat('${sender}')\" title=\"${i18n[currentLang].writePM}\">${formattedSender}</span>&gt; ${formattedText}`;\n\n} else {\n\ncontentSpan.innerHTML = `&lt;<span class=\"sender-name\" style=\"cursor:default;\">${formattedSender}</span>&gt; ${formattedText}`;\n\n}\n\n\n\nmsgDiv.appendChild(timeSpan);\n\nmsgDiv.appendChild(contentSpan);\n\nmessagesArea.appendChild(msgDiv);\n\n}\n\n\nfunction renderMessages(opts) {\n\nopts = opts || {};\n\nconst wasAtBottom = isChatAtBottom();\n\nconst prevScroll = messagesArea.scrollTop;\n\nmessagesArea.innerHTML = '';\n\nconst currentNick = nickInput.value.trim();\n\nif (activeTab === 'global') {\n\nglobalMessages.forEach(msg => {\n\nconst isSelf = (msg.sender === currentNick);\n\nappendMessageToDOM(msg.sender, msg.text, msg.time, isSelf, msg.isWeb);\n\n});\n\n} else {\n\nconst other = activeTab.replace('pm-', '');\n\nconst list = pmMessages[other] || [];\n\nlist.forEach(msg => {\n\nconst isSelf = (msg.from === currentNick);\n\n// All PMs are web communication\n\nappendMessageToDOM(msg.from, msg.text, msg.time, isSelf, true);\n\n});\n\n}\n\nif (opts.forceBottom || wasAtBottom) {\n\nmessagesArea.scrollTop = messagesArea.scrollHeight;\n\nhideScrollBtn();\n\n} else {\n\n// User is reading history above; keep their place and surface the button.\n\nmessagesArea.scrollTop = prevScroll;\n\nif (opts.newMessage) flashScrollBtn();\n\nelse updateScrollBtn();\n\n}\n\n}\n\n\nfunction switchTab(target) {\n\ndocument.querySelectorAll('.tab').forEach(t => {\n\nif (t.getAttribute('data-target') === target) {\n\nt.classList.add('active');\n\nt.classList.remove('unread');\n\n} else {\n\nt.classList.remove('active');\n\n}\n\n});\n\nactiveTab = target;\n\nrenderMessages({ forceBottom: true });\n\n}\n\n\nfunction closeTab(event, tabId) {\n\nevent.stopPropagation();\n\nconst tab = document.querySelector(`.tab[data-target=\"${tabId}\"]`);\n\nif (tab) {\n\ntab.remove();\n\nif (activeTab === tabId) {\n\nswitchTab('global');\n\n}\n\n}\n\n}\n\n\nfunction openPrivateChat(nick) {\n\nconst currentNick = nickInput.value.trim();\n\nif (nick === currentNick || nick === '[Server]') return;\n\n\n\nlet cleanNick = nick.replace(/ \\(Web\\)$/, '');\n\nif (cleanNick === currentNick) return;\n\n\n\nconst tabId = 'pm-' + cleanNick;\n\nlet tab = document.querySelector(`.tab[data-target=\"${tabId}\"]`);\n\nif (!tab) {\n\ntab = document.createElement('div');\n\ntab.className = 'tab';\n\ntab.setAttribute('data-target', tabId);\n\ntab.innerHTML = `${i18n[currentLang].pmWith}${cleanNick} <span class=\"tab-close\" onclick=\"closeTab(event, '${tabId}')\">&times;</span>`;\n\n\n\ntab.addEventListener('click', () => switchTab(tabId));\n\ntabsBar.appendChild(tab);\n\n}\n\nswitchTab(tabId);\n\nsidebar.classList.remove('open');\n\nchatsSidebar.classList.remove('open');\n\n}\n\n\nfunction renderChatsList() {\n\nchatsList.innerHTML = '';\n\nconst currentNick = nickInput.value.trim();\n\nconst chatPartners = Object.keys(pmMessages);\n\n\n\nif (chatPartners.length === 0) {\n\nconst emptyDiv = document.createElement('div');\n\nemptyDiv.style.color = '#777';\n\nemptyDiv.style.textAlign = 'center';\n\nemptyDiv.style.padding = '20px 0';\n\nemptyDiv.style.fontSize = '9px';\n\nemptyDiv.textContent = i18n[currentLang].noChats;\n\nchatsList.appendChild(emptyDiv);\n\nreturn;\n\n}\n\n\n\nchatPartners.forEach(partner => {\n\nconst row = document.createElement('div');\n\nrow.className = 'player-row clickable';\n\nrow.addEventListener('click', () => {\n\nopenPrivateChat(partner);\n\n});\n\n\n\nconst img = document.createElement('img');\n\nimg.className = 'player-avatar';\n\nimg.src = `/avatar/${partner}`;\n\nimg.onerror = function() { this.src = `https://minotar.net/helm/${partner}/32`; this.onerror=null; };\n\nimg.alt = '';\n\n\n\nconst name = document.createElement('span');\n\nname.className = 'player-name';\n\nname.textContent = partner;\n\n\n\nconst tabId = 'pm-' + partner;\n\nconst tab = document.querySelector(`.tab[data-target=\"${tabId}\"]`);\n\nif (tab && tab.classList.contains('unread')) {\n\nname.style.color = '#ff5555';\n\nname.textContent += ' (*)';\n\n}\n\n\n\nrow.appendChild(img);\n\nrow.appendChild(name);\n\nchatsList.appendChild(row);\n\n});\n\n}\n\n\nfunction loadHistory() {\n\nreturn fetch('/history')\n\n.then(res => res.json())\n\n.then(data => {\n\nglobalMessages = data;\n\nif (activeTab === 'global') renderMessages({ forceBottom: true });\n\n})\n\n.catch(err => console.error(\"Error loading history:\", err));\n\n}\n\n\nfunction loadPrivateHistory() {\n\nconst nick = nickInput.value.trim();\n\nif (!nick) return;\n\nfetch('/private/history?user=' + encodeURIComponent(nick))\n\n.then(res => res.json())\n\n.then(data => {\n\npmMessages = {};\n\ndata.forEach(msg => {\n\nconst other = (msg.from.toLowerCase() === nick.toLowerCase()) ? msg.to : msg.from;\n\nif (!pmMessages[other]) pmMessages[other] = [];\n\npmMessages[other].push(msg);\n\n});\n\nif (activeTab !== 'global') renderMessages({ forceBottom: true });\n\nif (chatsSidebar.classList.contains('open')) renderChatsList();\n\n})\n\n.catch(err => console.error(\"Error loading PM history:\", err));\n\n}\n\n\nlet eventSource;\nlet reconnectTimer;\nfunction connectSSE() {\n\nif (eventSource) {\n\neventSource.close();\n\neventSource = null;\n\n}\n\nif (reconnectTimer) {\n\nclearTimeout(reconnectTimer);\n\nreconnectTimer = null;\n\n}\n\n\n\nstatusPanel.className = 'status connecting';\n\nstatusText.textContent = i18n[currentLang].connecting;\n\n\n\nconst nick = nickInput.value.trim();\n\neventSource = new EventSource('/stream?nick=' + encodeURIComponent(nick));\n\n\n\neventSource.onopen = () => {\n\nstatusPanel.className = 'status';\n\nstatusText.textContent = i18n[currentLang].connected;\n\n};\n\n\n\neventSource.onerror = (e) => {\n\nconsole.error('SSE error', e);\n\nstatusPanel.className = 'status connecting';\n\nstatusText.textContent = i18n[currentLang].errorStatus;\n\nif (eventSource) {\n\neventSource.close();\n\neventSource = null;\n\n}\n\nif (!reconnectTimer) {\n\nreconnectTimer = setTimeout(() => {\n\nreconnectTimer = null;\n\nconnectSSE();\n\n}, 3000);\n\n}\n\n};\n\n\n\neventSource.onmessage = (event) => {\n\ntry {\n\nconst data = JSON.parse(event.data);\n\nconst currentNick = nickInput.value.trim();\n\n\n\nif (data.type === 'private') {\n\nif (data.from.toLowerCase() === currentNick.toLowerCase() || data.to.toLowerCase() === currentNick.toLowerCase()) {\n\nconst other = (data.from.toLowerCase() === currentNick.toLowerCase()) ? data.to : data.from;\n\nif (!pmMessages[other]) pmMessages[other] = [];\n\npmMessages[other].push(data);\n\nif (data.from && data.from.toLowerCase() !== currentNick.toLowerCase()) {\n    playNotificationSound();\n}\n\nconst otherTabId = 'pm-' + other;\n\nif (activeTab === otherTabId) {\n\nrenderMessages({ newMessage: true });\n\n} else {\n\nlet tab = document.querySelector(`.tab[data-target=\"${otherTabId}\"]`);\n\nif (!tab) {\n\ntab = document.createElement('div');\n\ntab.className = 'tab unread';\n\ntab.setAttribute('data-target', otherTabId);\n\ntab.innerHTML = `${i18n[currentLang].pmWith}${other} <span class=\"tab-close\" onclick=\"closeTab(event, '${otherTabId}')\">&times;</span>`;\n\ntab.addEventListener('click', () => switchTab(otherTabId));\n\ntabsBar.appendChild(tab);\n\n} else {\n\ntab.classList.add('unread');\n\n}\n\n}\n\n\n\nif (chatsSidebar.classList.contains('open')) {\n\nrenderChatsList();\n\n}\n\n}\n\n} else {\n\nglobalMessages.push(data);\n\nif (globalMessages.length > 150) globalMessages.shift();\n\nif (data.sender && data.sender !== '[Server]' && data.sender.toLowerCase() !== currentNick.toLowerCase()) {\n    playNotificationSound();\n}\n\nif (activeTab === 'global') {\n\nrenderMessages({ newMessage: true });\n\n} else {\n\ndocument.querySelector('.tab[data-target=\"global\"]').classList.add('unread');\n\n}\n\n\n\nif (data.sender === '[Server]' && (data.text.includes('joined') || data.text.includes('left'))) {\n\nloadServerInfo();\n\nloadPlayers();\n\n}\n\n}\n\n} catch (e) {\n\nconsole.error(\"Error parsing message\", e);\n\n}\n\n};\n\n}\n\n\nfunction loadServerInfo() {\n\nfetch('/server-info')\n\n.then(res => res.json())\n\n.then(data => {\n\nserverName.innerHTML = parseMinecraftColors(data.motd);\n\nupdateToggleSidebarBtnText(data.online, data.max);\n\nif (data.hasOwnProperty('clickerEnabled')) {\n\nopenClickerBtn.style.display = data.clickerEnabled ? 'block' : 'none';\n\n}\n\nif (data.hasOwnProperty('allowImageUploads')) {\n\nattachBtn.style.display = data.allowImageUploads ? 'block' : 'none';\n\n}\n\n})\n\n.catch(err => console.error(\"Error loading server info\", err));\n\n\n\nsrvIcon.src = '/server-icon.png?t=' + Date.now();\n\nsrvIcon.onerror = () => srvIcon.style.display = 'none';\n\n}\n\n\nfunction loadPlayers() {\n\nfetch('/players')\n\n.then(res => res.json())\n\n.then(data => {\n\nplayerList.innerHTML = '';\n\nif (data.length === 0) {\n\nconst emptyDiv = document.createElement('div');\n\nemptyDiv.style.color = '#777';\n\nemptyDiv.style.textAlign = 'center';\n\nemptyDiv.style.padding = '20px 0';\n\nemptyDiv.style.fontSize = '10px';\n\nemptyDiv.textContent = i18n[currentLang].noPlayers;\n\nplayerList.appendChild(emptyDiv);\n\nreturn;\n\n}\n\ndata.forEach(p => {\n\nconst row = document.createElement('div');\n\nif (p.isWeb) {\n\nrow.className = 'player-row clickable';\n\nrow.addEventListener('click', () => openPrivateChat(p.name));\n\n} else {\n\nrow.className = 'player-row';\n\n}\n\n\n\nconst img = document.createElement('img');\n\nimg.className = 'player-avatar';\n\nif (p.isWeb) {\n\nimg.src = `/avatar/${p.name}`;\n\nimg.onerror = function() { this.src = 'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22 fill=%22%23888888%22><path d=%22M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z%22/></svg>'; this.onerror=null; };\n\n} else {\n\nimg.src = `https://minotar.net/helm/${p.name}/32`;\n\n}\n\nimg.alt = '';\n\n\n\nconst name = document.createElement('span');\n\nname.className = 'player-name';\n\nname.textContent = p.name + (p.isWeb ? ' (Web)' : '');\n\n\n\nrow.appendChild(img);\n\nrow.appendChild(name);\n\nplayerList.appendChild(row);\n\n});\n\n})\n\n.catch(err => console.error(\"Error loading players list\", err));\n\n}\n\n\n\n        // ===== Authentication gate =====\n        let appStarted = false;\n        function initApp() {\n            if (appStarted) return;\n            appStarted = true;\n            loadServerInfo();\n            loadPlayers();\n            loadMyAvatar();\n            loadClickerStatus();\n            loadHistory().then(() => {\n                loadPrivateHistory();\n                connectSSE();\n            });\n        }\n\n        function setAccount(nick) {\n            nickInput.value = nick;\n            localStorage.setItem('mc_chat_nick', nick);\n            document.getElementById('auth-overlay').style.display = 'none';\n            initApp();\n        }\n\n        const authOverlay = document.getElementById('auth-overlay');\n        const authForm = document.getElementById('auth-form');\n        const authNick = document.getElementById('auth-nick');\n        const authPassword = document.getElementById('auth-password');\n        const authPassword2 = document.getElementById('auth-password2');\n        const authError = document.getElementById('auth-error');\n        const authSubmit = document.getElementById('auth-submit');\n        const authTabLogin = document.getElementById('auth-tab-login');\n        const authTabRegister = document.getElementById('auth-tab-register');\n        let authMode = 'login';\n\n        function setAuthMode(mode) {\n            authMode = mode;\n            authError.textContent = '';\n            authTabLogin.classList.toggle('active', mode === 'login');\n            authTabRegister.classList.toggle('active', mode === 'register');\n            authPassword2.style.display = (mode === 'register') ? 'block' : 'none';\n            const t = i18n[currentLang];\n            document.getElementById('auth-title').textContent = (mode === 'login') ? t.logIn : t.register;\n            authSubmit.textContent = (mode === 'login') ? t.logIn : t.register;\n            authTabLogin.textContent = t.logIn;\n            authTabRegister.textContent = t.register;\n            authNick.placeholder = i18n[currentLang].nickname;\n            authPassword.placeholder = t.passwordPh;\n            authPassword2.placeholder = t.confirmPh;\n            document.getElementById('auth-hint').textContent = (mode === 'register') ? t.authNickHint : '';\n        }\n        authTabLogin.addEventListener('click', () => setAuthMode('login'));\n        authTabRegister.addEventListener('click', () => setAuthMode('register'));\n\n        authForm.addEventListener('submit', (e) => {\n            e.preventDefault();\n            authError.textContent = '';\n            const nick = authNick.value.trim();\n            const password = authPassword.value;\n            if (authMode === 'register' && password !== authPassword2.value) {\n                authError.textContent = i18n[currentLang].passwordsMismatch;\n                return;\n            }\n            const url = (authMode === 'login') ? '/auth/login' : '/auth/register';\n            const params = new URLSearchParams();\n            params.append('nick', nick);\n            params.append('password', password);\n            authSubmit.disabled = true;\n            fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params })\n                .then(res => res.json().then(d => ({ ok: res.ok, d })))\n                .then(({ ok, d }) => {\n                    if (ok && d.status === 'ok') {\n                        authPassword.value = '';\n                        authPassword2.value = '';\n                        setAccount(d.nick);\n                    } else {\n                        authError.textContent = d.message || 'Error';\n                    }\n                })\n                .catch(() => { authError.textContent = 'Network error'; })\n                .finally(() => { authSubmit.disabled = false; });\n        });\n\n        document.getElementById('logout-btn').addEventListener('click', () => {\n            fetch('/auth/logout', { method: 'POST' }).finally(() => location.reload());\n        });\n\n        // Decide on load: valid session -> start app, otherwise show the login overlay.\n        fetch('/auth/me')\n            .then(res => res.json().then(d => ({ ok: res.ok, d })))\n            .then(({ ok, d }) => {\n                if (ok && d.status === 'ok') {\n                    setAccount(d.nick);\n                } else {\n                    setAuthMode('login');\n                    authOverlay.style.display = 'flex';\n                    authNick.focus();\n                }\n            })\n            .catch(() => {\n                setAuthMode('login');\n                authOverlay.style.display = 'flex';\n            });\n\n        openClickerBtn.addEventListener('click', () => {\n            loadClickerStatus();\n            clickerModal.classList.add('open');\n            if (activeClickerTab === 'furnace') {\n                startFurnacePolling();\n            }\n        });\n        closeClickerBtn.addEventListener('click', () => {\n            clickerModal.classList.remove('open');\n            stopFurnacePolling();\n        });\n        clickerBlock.addEventListener('click', clickBlock);\n        transferSendBtn.addEventListener('click', transferOre);\n        transferMaxBtn.addEventListener('click', () => { if (selectedOreSlot) transferAmountInput.value = clickerInventory[selectedOreSlot] || 1; });\n\n        setInterval(() => {\n            loadServerInfo();\n            loadPlayers();\n        }, 15000);\n\n        chatForm.addEventListener('submit', (e) => {\n            e.preventDefault();\n            const text = msgInput.value.trim();\n            if (!text) return;\n            msgInput.value = '';\n            sendMessage(text);\n        });\n\n        // --- Emoji picker ---\n        emojiBtn.addEventListener('click', (e) => {\n            e.preventDefault();\n            e.stopPropagation();\n            const hidden = (emojiPicker.style.display === 'none' || emojiPicker.style.display === '');\n            emojiPicker.style.display = hidden ? 'grid' : 'none';\n        });\n\n        emojiPicker.querySelectorAll('span').forEach(span => {\n            span.addEventListener('click', () => {\n                const emoji = span.textContent;\n                const start = (typeof msgInput.selectionStart === 'number') ? msgInput.selectionStart : msgInput.value.length;\n                const end = (typeof msgInput.selectionEnd === 'number') ? msgInput.selectionEnd : msgInput.value.length;\n                msgInput.value = msgInput.value.slice(0, start) + emoji + msgInput.value.slice(end);\n                const pos = start + emoji.length;\n                msgInput.focus();\n                try { msgInput.setSelectionRange(pos, pos); } catch (err) {}\n                emojiPicker.style.display = 'none';\n            });\n        });\n\n        // Close the emoji picker when clicking elsewhere\n        document.addEventListener('click', (e) => {\n            if (emojiPicker.style.display !== 'none' && !emojiPicker.contains(e.target) && e.target !== emojiBtn) {\n                emojiPicker.style.display = 'none';\n            }\n        });\n\n        // --- Image / GIF upload ---\n        attachBtn.addEventListener('click', (e) => {\n            e.preventDefault();\n            const nick = nickInput.value.trim();\n            if (!nick) { alert(i18n[currentLang].enterNick); return; }\n            fileInput.click();\n        });\n\n        fileInput.addEventListener('change', () => {\n            const file = fileInput.files[0];\n            if (!file) return;\n            const nick = nickInput.value.trim();\n            if (!nick) { alert(i18n[currentLang].enterNick); fileInput.value = ''; return; }\n\n            const sendBtnEl = document.getElementById('send-btn');\n            const prevLabel = sendBtnEl ? sendBtnEl.textContent : '';\n            if (sendBtnEl) { sendBtnEl.textContent = i18n[currentLang].sending; sendBtnEl.disabled = true; }\n\n            fetch('/upload?name=' + encodeURIComponent(file.name), {\n                method: 'POST',\n                headers: { 'Content-Type': 'application/octet-stream' },\n                body: file\n            })\n            .then(res => res.json())\n            .then(data => {\n                if (data && data.url) {\n                    sendMessage('[img]' + data.url + '[/img]');\n                } else {\n                    alert((data && data.error) ? data.error : i18n[currentLang].errorUploading);\n                }\n            })\n            .catch(err => {\n                console.error('Upload error', err);\n                alert(i18n[currentLang].errorUploading);\n            })\n            .finally(() => {\n                fileInput.value = '';\n                if (sendBtnEl) { sendBtnEl.textContent = prevLabel; sendBtnEl.disabled = false; }\n            });\n        });\n\n        // The global chat tab is static markup, so wire its click handler too\n        // (PM tabs get theirs on creation). Without this you could not switch\n        // back to global chat without closing the private conversation.\n        document.getElementById('tab-global').addEventListener('click', () => switchTab('global'));\n\n        // Apply the saved/default language once at startup so static labels\n        // (e.g. the furnace tab) are localized without waiting for a manual switch.\n        updateLanguageUI();\n    </script>\n</body>\n</html>";

    private static final String INDEX_HTML = INDEX_HTML_PART1 + new String(INDEX_HTML_PART2) + new String(INDEX_HTML_PART3);

    private static final String NOTIFY_WAV_PART1 = "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1//O/8X/v/+6/7X/sf+v/67/r/+v/7H/s/+3/7n/wv/G/87/1f/e/+X/7v/1//7/AQAGAAwAEQAYABoAHwAkACgALAAvADUAOAA6ADsAPQA+AD8AQAA/AD4APAA4ADYAMwAuACYAIAAaABMACwADAPz/8//q/+P/2//U/87/yv/D/8L/vf++/73/u/+9/8D/wv/E/8j/zf/T/9j/3v/m/+z/9P/6//7/AgAIAAsADwAVABcAGwAfACMAJgAoACwALQAwADAAMwAxADMAMgAwADEALwArACgAJgAiABoAFwARAAwABgAAAPn/9P/t/+b/4f/a/9f/1P/R/83/yv/K/8v/y//K/83/zv/S/9j/2v/e/+T/6f/v//X/+f///wEAAwAGAAoADQAQABQAFwAZABsAHQAgACEAIgAjACMAJQAkACYAIwAmACMAIwAgAB4AHQAYABYAEgAMAAkABQD///z/9v/v/+z/6P/j/9//3P/Z/9n/1//X/9f/1v/X/9j/2f/e/9//5P/n/+3/8P/0//f/+////wIABAAJAAkACwANABAAEAAUABYAFgAXABoAGgAZABsAHAAdAB0AHgAcABwAGwAaABkAFgAUABIADwALAAcABAD///z/+P/z/+7/7P/n/+X/5P/i/9//3//c/93/3v/d/9//4P/j/+X/6P/u/+//8v/3//n//P8AAAIAAwAFAAcABwAKAAwADAAPABIAEwATABMAFQAYABkAGQAaABgAGQAYABkAGAAWABQAEwARAA8ADAAHAAQAAgD///v/+P/z//H/7f/s/+n/5//l/+X/4//j/+L/4//m/+X/5v/p/+r/6//v//P/9v/3//z//v8AAAAAAgAEAAQABwAJAAoADAANABAAEgASABIAFQAVABQAFwAVABUAFgAUABQAEgARAA8AEAANAAkACAAFAAIAAAD9//v/9//1//P/8P/t/+v/6v/p/+r/6f/p/+j/6f/p/+r/6//s/+7/8f/y//X/+f/6//z//v8AAAEAAgADAAYABQAHAAoACwANAA4ADgARAA8AEQAPABMAEAARABEAEQASAA4ADgANAA4ACwAJAAcABgADAAEAAAD8//v/9//2//T/8//w/+//7//u/+//7f/v/+7/7f/v/+7/8P/x//T/9P/2//f/+v/7//3//////wAAAAADAAQABAAFAAcACAAJAAsACgAMAAwADQAOAA0ADgAQAA0ADQANAAwACwALAAoABwAIAAUABQABAAEAAAD+//v/+P/5//b/9f/z//X/8//x//L/8f/y//L/8//x//P/9P/0//b/9//6//r/+//8///////+/wAAAQADAAMAAQAEAAYABgAGAAYACgAIAAkACwALAAkACgALAAoACwAKAAkACAAKAAcABwAGAAMABAACAAEA/v/+//3/+//4//j/9v/2//X/9v/1//T/9P/1//T/9P/1//f/9f/3//j/+v/7//n//f/9//3/AAAAAP//AQAAAAMAAgACAAQABQAFAAcABwAGAAgACAAKAAcACgAIAAkACQAJAAgABgAHAAcABQAFAAMAAwACAP///////////P/7//r/9//3//j/9//3//b/9f/3//f/9v/2//n/+f/5//r/+v/7//z//////////////wEAAQABAAIAAQADAAIAAwADAAQABAAFAAcABQAGAAYABQAGAAQABQAGAAYABAAEAAUAAwADAAEA//8BAP////////3//f/7//z/+v/5//r/+f/3//f/+f/5//r/+//5//n/+//8//3//P/+///////+/wAAAAAAAAAAAQAAAAIAAAACAAIAAgACAAMAAwAEAAMAAwADAAMABAAEAAMABAADAAMABAAEAAEAAQABAAAAAAAAAAAA//////3//P/8//z/+v/7//z//P/6//v/+v/7//n/+//8//3/+//9//7//f////////////////8BAAAAAQABAAAAAQACAAMAAgABAAMAAgACAAMAAwADAAEABAADAAMAAwADAAEAAwACAAEAAgABAAEAAAD///7/AAD+//z//f/9//3//f/7//z//f/7//v//f/9//3//P/8//3//v/+//7//v/+//////8AAP//AAAAAAAAAQABAAEAAQABAAIAAAACAAEAAgABAAIAAwACAAIAAwACAAEAAQADAAIAAwABAAEA//8AAAAA//////3///////3//v/9//3//f/8/////v/9//3//P/9/wAA/f////7//v//////////////AAD/////AAAAAAEAAQABAAAAAAAAAAEAAAACAAAAAgADAAIAAQABAAIAAgAAAAIAAwAAAAIAAQABAP//AAAAAAAAAAAAAAAA///+/////f///wAA/P/+//3//f/+///////+//3//P////7//v8AAP7/////////AAD+/wAA/////wAAAQD/////AgABAAAAAAAAAAEAAQABAAIAAAABAAAAAgAAAAEAAQABAAAAAAAAAAAA//8AAAAA/////////////////v////7///////7//v/+//7//v///wAA///+//7//////wAA//8AAP////8AAP////8AAAAA/////wEAAAAAAAEAAAAAAAEAAAAAAP//AAAAAP////8AAAAAAAAAAP////8AAAEAAAAAAP//AAD//////v8AAP7//////wEAAAD+////AQD//////v///wAA//8AAP///v////7/AAD//wAA/////wAAAAAAAAAAAAAAAAAA//8AAP//AAAAAAEA/////wAA/////wAA//8CAP//AAD//wAAAAD/////AgD///7/AAD/////AAD///////8AAP////8AAAAAAAAAAP///////wAAAAD//wAA/////wAA//8AAP//AAAAAAAAAAD/////AAD+////AQAAAP//AAAAAAAA//8AAAAA//8AAP////8AAAAA/v///wAAAAD+/wAA/////wAAAAD//////////wAAAAABAP//////////AAD//wAA////////AAAAAAAA//8AAAAAAAD/////AAAAAAAA/v8AAAAA/////wAA/////wAA///////////+////AAAAAP////8AAAAA//8AAP//AAD/////AAAAAAAAAAAAAP////8AAAAAAAAAAP//AAAAAAAA/////wAAAAAAAP//AAD//wAAAAAAAP//////////AAD/////AAAAAAAAAAD+////////////AAAAAAAA/////////v8AAP///v///wAA//8BAP//AAD/////AAAAAP//AAAAAP//AAD//wAA/v///wAAAAAAAP//AQD+//////8AAAAAAAD/////AAAAAAAAAAD//////////wEA//8AAP///////wAA/////wAA///+////AAAAAP////8AAAAAAAD+/////////wAA////////AAAAAP////8AAAAA////////AAAAAP///v8AAAAAAAAAAP7///8BAAAAAAAAAAAA///+/wAAAAAAAP//AAAAAP//AAD/////AAAAAP7//v8AAAAAAAAAAAAA///+//7/AAD//wAAAAD///7///8AAAAA///+////AQAAAAAAAAAAAAAA//8AAAAA////////AAD/////AAD+/wAAAAAAAAAAAAD//wAAAAABAP///////wAAAAD+//////8AAAAAAQD//wAAAAD//wAA//////////8AAAAAAQD+////AAD//wAA/////wAA//8AAAAAAAD//wAA/v8AAAAA/f8AAAAAAAAAAP///////////////wAA//8AAP////8AAP//AAAAAP//////////AAAAAP//AAAAAAAA////////AAAAAAAAAAD//////////wAAAAD//wAAAAD//////////wAAAAAAAP///////wAAAAAAAP////8AAP//AAABAP//AAAAAAAAAAABAAAA//8AAP//AAAAAAAA/////wEA//8AAP//AAD//wAA/////wAA/////wAA/////wAAAAD+//////8AAP////8AAP////8AAAAAAAD/////AAAAAAAA//8AAP////8AAAAAAAAAAAAA/////wAAAAD//wAAAAD//////v8AAAAAAAAAAAAAAAD+/wAAAAD//wAAAAAAAP////8AAAAAAQAAAP//AAD///////8AAAAAAAAAAP////8AAAAAAAAAAP7//////wAA//8AAP7///8AAAAA//8AAP////8AAAAAAQAAAP////8AAP//AAAAAP//AAAAAP////8AAP////8AAP//AAAAAP7///8AAP//AAAAAP//AAD//wAA/////wAAAAD//wAA//////////8AAP//AAAAAAAA/////wAAAAD//wAA//8BAAEA//8AAAAAAAAAAP//AQAAAAAA//8AAP/////9/wAAAAAAAAAA/////wAAAAAAAAAAAAAAAP//////////AAAAAP////8AAP//////////AAAAAP//AAAAAP//////////AAD+//7/AAD//////f8AAAAAAAD+/wEAAAAAAAAAAAAAAP//AAAAAP//////////AAD///////8AAAAAAAAAAP3/AAAAAAAA//8AAAAA/////wAAAAD///7/AAAAAAAAAAD///////8AAAAAAAD//wAA//8AAP////8AAP//AAD/////AAAAAAAAAAD/////AAABAP//AAD//wAAAAAAAAAA//8AAAAAAAAAAAAA/v8AAAAA/v///wAA/v///wEAAAD//////v8AAP////8AAAEA////////AQAAAP///v///wAA//8BAAAA//8AAP//AAAAAP7/AAD+///////+////AAD/////AAABAP//AAD//////////wAA/////////////////////wAA/////wAAAAABAP////8AAAAAAAAAAP7/AQD//wAA/////wAAAAABAAAA//8AAAAA////////////////AQAAAP///////wEAAAD//////////wEAAAABAP////8BAAAAAAD/////////////AAAAAAAA////////AAAAAP////8AAAAAAQD/////AAAAAAAA////////AAD///7/AAAAAAAA///+/wAAAAD//////////wAAAAAAAP///////wAA/////wAAAAAAAP////8AAP//AAD//wAA//8AAAAAAAD//wAA/////wAAAAD///7/AAD//wAAAAD//wAA//8AAAAAAAAAAAAAAAAAAP////8AAP////8AAP/////+////AAAAAAAA//8AAP7/AAAAAP///////wAA//8AAP//////////AAD//wAA//8AAAAA/////wAAAAAAAP///////wAA//8AAAAA//////////8AAP7///8AAAAAAAD//wAA//8AAAAAAAD/////AAAAAAAA//8AAP////8AAP//AAAAAAAA/////wAAAAAAAAAAAAD/////AAD//wAAAAAAAP////8AAAAA//8AAAAA/////wAA//8AAP//AAAAAAAA//8AAP////8AAAAAAAAAAAAA////////AAAAAP////8AAAAAAAAAAAAA////////AAAAAP////8AAP//AAD//wAA//8AAAAAAAAAAP////8AAAAA//////////8AAAAA//8AAP///////wAAAAAAAP///////wAAAAD///////8AAP////8AAAAA///+/wAAAAD/////AAAAAAAAAAD///////8AAAAAAAAAAP///////wAAAAAAAP//AAAAAP//AAD//wAA/////wAAAAAAAP////8AAAAA//8AAAAA/////////////wAAAAD//////////wAAAAD///////8AAAAAAAAAAAAAAAD//////////wAAAAD//wAAAAD///////8AAP//AAD//wAAAAD/////AAD///////8AAAAAAAAAAP////8AAP//AAAAAAAAAAD///////8AAAAA/////wAAAAD/////AAAAAAAA//8AAAAAAAAAAAAA////////AAAAAP////8AAAAA/////wAA/////wAAAAAAAAAA/////wAAAAD/////AAAAAP////8AAAAAAAAAAP///////wAA//8AAAAAAAD//wAA/////wAA/////wAAAAAAAAAA//8AAAAAAAAAAAAAAAD///7/AAAAAAAAAAD//wAA//8AAP//AAAAAAAAAAD/////AAD/////AAAAAAAAAAAAAAAA////////AAAAAP//AAD/////AAAAAP//AAAAAP//////////AAAAAP////8AAP////8AAP////8AAP//AAAAAAAA//////////8AAAAA//8AAAAA/////wAA//8AAAAA////////AAAAAP//////////AAAAAP//AAAAAP//AAAAAAAA//8AAAAAAAD//wAAAAD///////////////8AAAAAAAAAAP//////////AAAAAAAA////////AAD/////AAAAAP////8AAP//AAD//wAA//8AAAAAAAD/////AAAAAAAAAAD//wAA//8AAP//AAAAAP///////wAAAAAAAP////8AAP//AAAAAAAAAAAAAAAA/////wAA/////wAA//8AAAAAAAAAAP//AAD//wAAAAD/////AAAAAAAAAAAAAP//AAD/////AAAAAAAA//8AAP////8AAP///////wAA//8AAAAA//////////8AAAAA/////wAAAAAAAAAA////////AAAAAAAA//8AAP////8AAAAAAAD//wAAAAD/////AAD///////8AAAAAAAD///////8AAAAA//////////8AAP//AAAAAP////8AAP//AAAAAAAA//8AAP//AAAAAAAA/////wAA//8AAP////8AAAAA//8AAAAA/////wAAAAD/////AAAAAP///////wAAAAAAAAAA//8AAAAA//8AAAAA//8AAP//AAD///////8AAAAA/////wAA/////wAA/////wAAAAAAAP////8AAP////8AAAEAAAD/////AAD/////AAD//wAAAAD/////AAD///////8AAAAA//////////8AAAAAAAD//wAAAAD/////AAD///////8AAAAA///+/wAAAAD/////AAAAAP////8AAAAAAAD/////AAD//wAAAAAAAP///v///wAAAAAAAP////8AAAAA//8AAAAA//////////8AAAAAAAD/////AAD///////8AAAAA/////////////wAAAAAAAP//AAD//wAAAAD/////AAAAAAAA//////////8AAAAA////////AAAAAP//AAD//wAAAAD//wAA/////wAA/////wAAAAD/////AAAAAP////////////8AAP////8AAAAA//8AAAAA////////AAD/////AAAAAP//AAD/////AAAAAP///////wAA/////wAA//8AAP//////////AAD//wAA//8AAAAA/////wAAAAD///////8AAP////8AAAAAAAD//wAAAAAAAP////8AAAAA/////wAAAAAAAP//AAD/////AAAAAP//AAAAAP///////wAAAAAAAP////8AAAAA////////AAAAAAAA//////////////////8AAP///////wAAAAD///////8AAAAAAAAAAP//AAAAAAAA////////AAAAAAAAAAD/////AAAAAAAAAAD//wAA////////AAD//wAA//8AAAAAAAD///////8AAAAA//8AAP////////////8AAP//AAAAAP///////wAAAAAAAP//AAAAAAAAAAD/////AAAAAAAA//8AAP//AAAAAP////8AAP//AAAAAAAA//8AAAAAAAAAAAAAAAAAAAAAAAD/////AAD///////8AAAAAAAD/////////////AAAAAAAA/////////////wAA/////wAA/////////////wAAAAAAAP////8AAAAAAAD/////AAAAAP//////////AAAAAP////8AAAAA/////wAAAAAAAP//AAD//wAAAAD//wAAAAAAAP////8AAAAA//8AAAAA/////wAA//8AAAAA//8AAP//AAD//wAAAAAAAAAAAAD///////8AAP//AAAAAAAA////////AAD//wAAAAAAAP///////////////wAAAAAAAAAAAAD//wAAAAAAAP//AAD///////8AAAAAAAAAAP////8AAAAA////////AAAAAP//AAAAAP//AAD/////AAAAAAAA//8AAP////8AAAAAAAAAAAAA/////wAA//////////8AAAAA//8AAAAA//8AAAAA////////AAAAAP////8AAP///////wAAAAAAAAAA//////////8AAP////8AAAAAAAD//wAAAAD//wAAAAAAAP//AAAAAAAAAAAAAP////8AAAAA//8AAP////8AAAAA//8AAP//AAAAAAAA/////wAAAAD/////AAAAAP//AAD//wAA/////wAAAAD/////AAAAAP////8AAAAA////////AAD//wAAAAAAAAAAAAD///////////////8AAAAA//8AAAAA//8AAP//AAD/////AAD/////AAD//wAAAAAAAAAA/////wAAAAD///////8AAAAAAAAAAAAA////////AAAAAAAAAAD//wAA/////wAAAAD//wAA/////wAAAAAAAP//AAD//wAAAAD///////8AAAAA////////AAAAAP//AAAAAAAA//8AAP//AAAAAP///////wAAAAAAAAAAAAD//wAAAAAAAP///////wAAAAAAAAAA/////wAA//8AAP//////////AAAAAAAA/////wAAAAAAAP//AAAAAAAA//8AAAAA//8AAAAA//8AAAAAAAD//////////wAA//8AAP////8AAAAAAAD/////AAAAAAAA////////AAAAAAAA////////AAAAAP////8AAAAAAAD/////AAD///////8AAAAAAAAAAP///////wAAAAAAAP////8AAP////8AAAAAAAD//wAA////////AAAAAP////8AAAAA/////wAAAAAAAP//AAAAAAAAAAD/////AAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAP///v///wAA//8AAAAA/////wAAAAD/////AAD//wAAAAAAAAAAAAAAAP//AAAAAP//AAD/////AAAAAAAA//8AAAAAAAAAAP////8AAAAA/////wAA/////wAAAAD/////AAAAAP//////////AAAAAP////8AAAAAAAD/////AAAAAP///////wAAAAD//wAAAAAAAP////////////8AAAAA////////AAAAAP//AAAAAP//AAD//wAA//8AAAAA//8AAP//AAD//wAAAAD//wAA//8AAP///////wAAAAD/////AAAAAAAA//8AAAAA/////wAA////////AAAAAAAA/////wAA//8AAAAA//8AAAAA//8AAP//////////AAAAAP///////wAAAAD/////AAD/////AAAAAAAAAAAAAAAAAAAAAP////8AAP////8AAAAA//8AAP////8AAAAAAAAAAP//////////////////AAD//wAAAAD//wAA/////wAA/////wAAAAAAAAAA////////AAAAAP////8AAAAA//8AAP////8AAAAAAAAAAP7/AAAAAAAA/////wAA//8AAP////8AAAAAAAD/////AAD/////AAAAAP////8AAP////8AAAAAAAD///////8AAAAA////////AAAAAP////8AAP///////wAAAAAAAP///////wAAAAD//wAA//8AAP///////wAA////////AAAAAAAA//8AAAAA//8AAAAAAAAAAP//AAAAAAAA//////////8AAAAAAAAAAAAAAAD/////AAAAAP//////////AAD/////AAD///////8AAAAA//8AAAAAAAAAAAAA//8AAAAAAAAAAAAAAAAAAAAA//8AAP///////wAAAAD//wAAAAAAAP////////////8AAAAAAAD/////AAD///////8AAP///////wAAAAD//wAA//8AAP////8AAAAA//8AAP//AAD/////AAAAAAAA////////AAAAAAAA//8AAAAA//8AAP///////wAAAAAAAAAAAAAAAP//AAAAAP//AAAAAP//////////AAD///////////////8AAAAA//8AAAAA/////wAAAAD/////AAAAAP////8AAAAAAAD///////8AAAAAAAD//////////wAAAAAAAP////8AAAAA////////AAD//wAAAAAAAAAA//8AAAAA//////////8AAP////8AAAAAAAD/////AAD//wAAAAD///////8AAAAA/v8AAAAAAAD//wAAAAD/////AAD/////AAAAAAAAAAD///////8AAP//AAAAAP//AAAAAP///////wAAAAAAAP///////wAAAAD/////AAAAAP//////////AAAAAP//AAAAAAAA//8AAAAA//8AAAAA////////AAD//wAA/////wAAAAAAAAAA//8AAP//AAAAAAAAAAD/////AAD/////AAAAAP///////wAAAAD/////AAAAAP//AAAAAAAAAAAAAP//AAAAAAAA//8AAP//////////AAD/////AAAAAAAA////////////////AAAAAP////8AAP////8AAAAAAAD//wAA//8AAP////////////8AAAAAAAAAAP//AAD//wAAAAD//wAA//8AAAAA/////wAAAAD/////AAAAAAAA/////wAA//8AAP//AAAAAP////8AAP//AAD/////AAAAAAAAAAAAAP///////wAAAAAAAP////8AAP////8AAAAA/////wAAAAAAAP////8AAP//AAAAAAAAAAD/////AAAAAAAAAAD/////AAAAAP//AAAAAP//AAD///////8AAP//AAAAAP////8AAP//AAAAAP//////////AAAAAAAAAAD//wAAAAD//wAAAAD/////AAAAAP//AAAAAAAA////////AAAAAP//AAD/////AAD//wAAAAAAAP////8AAP////8AAAAA/////wAA//8AAAAA//8AAAAAAAD//////////wAAAAAAAP///////wAAAAD///////8AAP//AAAAAP////8AAAAAAAD/////AAAAAAAAAAD//wAAAAAAAAAAAAD/////AAAAAP//AAD///////8AAAAAAAD/////AAAAAAAA//8AAAAA////////AAAAAAAA////////AAAAAAAA/////wAAAAAAAP////8AAAAA/////wAA//////////8AAAAA////////AAAAAAAAAAD/////AAAAAP////8AAAAA//8AAAAA/v///wAAAAAAAP//AAAAAP//////////AAD/////AAD/////AAAAAAAAAAD//wAA//8AAP////8AAAAA//8AAP///////wAAAAD//wAA/////wAAAAD//wAAAAAAAAAA////////AAAAAP//AAAAAP//AAAAAAAAAAAAAAAA/////wAA//8AAAAA//8AAP//AAD//wAA//8AAP//AAAAAP//AAAAAP//AAAAAP////8AAAAAAAAAAP///////wAA//8AAP//AAD///////8AAAAA//8AAAAA/////wAAAAD/////AAAAAAAAAAAAAP////8AAAAA////////AAD//wAAAAD/////AAAAAP////8AAAAAAAAAAP////8AAP//AAD//wAAAAAAAAAA///+////AAAAAAAA//8AAAAA//8AAAAA////////AAAAAAAAAAD//wAAAAAAAAAAAAD/////AAAAAP////////////8AAP//////////AAAAAAAA//8AAAAA//8AAAAA////////AAD//wAAAAAAAP////8AAAAAAAAAAAAA/////wAAAAD/////AAAAAP///////wAAAAD/////AAD//wAA////////AAAAAP//AAAAAP////8AAAAAAAD/////AAD/////AAAAAP////8AAP//AAD//wAA//8AAP//AAAAAAAAAAD//////////wAA/////wAA//8AAAAAAAD/////AAAAAP////8AAAAAAAD//wAAAAD/////AAD//wAA//8AAAAA//8AAAAA/////wAAAAD//wAAAAAAAP////8AAP////8AAAAA/////wAAAAD//wAAAQD///////8AAP////8AAAAAAAD//wAA//8AAP//AAD//wAAAAAAAP//AAD//////////wAA/////wAA/////wAAAAAAAP////8AAAAA//8AAAAAAAAAAAAA/////wAAAAD//wAA/////wAA//8AAAAA//8AAP//AAAAAP////8AAP////8AAP///////wAAAAAAAP////8AAAAAAAD//wAA/////wAA//////////8AAAAA/////wAAAAAAAP////8AAP///////wAAAAAAAP///////wAA/////wAA//8AAAAAAAAAAP//AAD//wAAAAD//wAAAAAAAAAA////////AAD/////AAAAAP////8AAP////8AAAAAAAD//////////wAAAAD//wAAAAAAAP////8AAAAAAAD/////AAD/////AAAAAAAAAAAAAAAAAAAAAP//AAAAAAAA/////wAA/////wAAAAD//wAAAAD//wAA//8AAAAA//8AAP////8AAAAAAAD//wAAAAAAAAAA//8AAAAAAAD/////AAD//////////wAAAAD//wAAAAD///////8AAAAAAAAAAAAA/////wAAAAAAAAAA/////wAAAAAAAP//AAD/////AAD///////////////8AAAAA/////wAAAAD/////AAD//wAAAAD/////////////AAAAAP//AAD//wAAAAD/////AAD/////AAD//wAA////////AAAAAP//AAD///7///8AAAAA/////wAA//8AAP////8AAAAAAAD//wAAAAD/////AAAAAP//AAAAAAAA////////AAD//wAAAAAAAP///////wAAAAD//wAA/////wAA/////wAAAAD/////AAD//////////wAAAAD//////////wAAAAAAAP//////////AAD//wAAAAAAAP///////wAAAAD/////AAAAAAAA//////////8AAAAA//8AAP//////////AAAAAP///////wAA//8AAAAAAAD//wAAAAD///////8AAP//AAD//wAA/////wAAAAD/////AAAAAAAA/////wAAAAD/////AAAAAP////8AAAAAAAD//wAAAAD/////AAAAAP////////////8AAAAAAAD//wAAAAD///////8AAP///////wAAAAAAAAAA//8AAP//////////AAD/////AAAAAP////8AAP//AAAAAAAA/////wAA////////AAD//wAAAAAAAAAA//8AAAAAAAD/////AAD//wAAAAD//wAAAAD//wAA//8AAP//////////AAAAAAAAAAAAAP///////wAAAAAAAP//////////AAD/////////////AAD/////AAAAAAAA//8AAP///////wAAAAAAAP//AAD//wAAAAAAAP//AAD/////AAAAAP////////////8AAAAA/////wAAAAAAAP//AAAAAP///////wAAAAD/////AAAAAAAA//////////8AAAAAAAAAAP//AAD//wAA//8AAAAA/////wAAAAAAAP//////////AAAAAP////8AAAAA/////wAA//8AAAAAAAAAAAAA/////wAAAAD/////AAAAAP////8AAP//AAAAAP///////wAAAAAAAP//AAD/////AAAAAP//AAAAAAAAAAD/////////////AAD//wAA//////////8AAAAA/////wAAAAD///////8AAAAAAAAAAP////////////8AAAAAAAAAAAAA//////////8AAAAA//8AAAAAAAD///////8AAP//AAD///////8AAAAA//////////8AAAAA//8AAAAAAAD/////AAD///////8AAP//AAAAAP////8AAAAA//8AAAAA//////////8AAAAA/////wAA//8AAP////////////8AAAAAAAD//wAAAAAAAAAA/////wAAAAD///////8AAAAAAAD/////AAAAAP////8AAP///////wAAAAAAAP//AAD//wAAAAAAAAAAAAAAAAAA/////wAAAAD/////AAAAAP//AAD+////AAAAAAAAAAAAAAAAAAAAAP////8AAAAA/////wAA/////////////wAA//8AAAAA//8AAP///////wAA////////AAAAAP//AAD///////8AAAAA////////AAAAAP//AAAAAP///////wAAAAAAAAAA////////AAAAAAAAAAD///////8AAAAAAAD//wAA//////////8AAAAAAAD/////AAAAAP//AAD//wAA/////wAAAAD/////AAD//wAAAAD//////////wAA/////wAAAAD//wAAAAAAAP//AAD//wAAAAAAAAAA//////////8AAP//AAAAAAAAAAAAAAAA/////wAAAAD/////AAAAAP////8AAP//AAAAAAAA//8AAAAAAAAAAP////8AAP////8AAAAA//////////8AAAAAAAD/////AAAAAAAA/////////v///wAAAAD/////AAAAAAAA//8AAAAA////////AAD/////AAAAAAAA/////////////wAA//8AAAAAAAAAAAAA/////wAAAAAAAAAA//8AAP///////wAA/////wAAAAAAAP//////////AAAAAP////8AAP///////wAA//8AAP///////wAAAAAAAP////8AAAAAAAD//wAA//////////8AAAAA//8AAP//AAAAAAAA//8AAP///////wAA////////AAD/////AAAAAP////8AAAAAAAD/////AAAAAAAA//////////8AAAAAAAAAAP//AAAAAP////8AAAAA////////AAAAAAAA//////////8AAP//AAD/////AAD/////AAAAAP////8AAAAAAAD//wAAAAD///////8AAAAA//8AAP///v///wAAAAD/////AAAAAAAA/////wAAAAD//wAA//8AAAAA////////////////AAAAAAAA//8AAP///////wAA//////////8AAAAAAAAAAP//AAAAAAAA//////////8AAP//AAAAAAAAAAD//wAA////////AAD/////AQAAAP////8AAAAA//8AAAAAAAD/////AAD/////AAAAAAAAAAD/////AAAAAP////8AAAAA/////wAA//8AAP////8AAP//AAAAAP//AAAAAAAA//8AAAAA////////////////AAAAAP////8AAAAA//8AAP///////wAA/////wAAAAAAAP//AAD/////AAAAAP//////////AAAAAP//AAAAAAAA////////AAD//wAAAAAAAP//AAAAAAAA//8AAAAAAAD/////////////AAD///////8AAAAA/////wAAAAD/////AAAAAP///////wAA//8AAAAAAAD//wAAAAAAAAAAAAAAAAAA/////wAAAAD//wAAAAAAAAAA//8AAP//////////AAD/////////////AAAAAP////////////8AAAAAAAAAAAAA/////wAA//8AAAAA////////AAD//wAAAAAAAAAA/////wAAAAD///////////////8AAP//AAD///////8AAP////8AAAAA//////////8AAAAAAAD/////////////AAD/////AAAAAP////8AAAAAAAD//wAAAAAAAP////8AAAAAAAD/////AAAAAAAAAAAAAAAA/////wAAAAD/////AAAAAAAA//8AAP////8AAAAAAAAAAP////8AAAAA/////wAA//8AAAAA//8AAP////8AAP////8AAAAA///+////AAAAAP//AAAAAP////8AAAEA/////////////wAAAAD//wAAAAAAAAAA//8AAAAA//8AAP///////wAA/////wAAAAAAAP////8AAAAA//8AAAAA//8AAAAAAAD//wAAAAD/////AAAAAAAAAAAAAP//////////AAD/////AAAAAAAA/////wAAAAD//wAAAAD//wAAAAD/////AAD//wAAAAD///////8AAP////8AAAAAAAAAAP////8AAAAAAAD//wAA//////////8AAP//AAD//wAA/////wAAAAD//////////wAAAAAAAAAA//////////8AAP////8AAAAAAAD///7///8AAAAA////////AAAAAP//////////AAD//wAAAAD/////AAAAAAAA//8AAAAAAAAAAP//AAD/////AAAAAP///////wAAAAAAAP//AAAAAP////8AAP//AAAAAP///////wAAAAAAAP////8AAP//////////AAAAAP////8AAAAA//8AAAAAAAD//wAAAAD/////AAD///////8AAAAAAAAAAP//////////AAAAAAAA//8AAP//AAAAAP//AAAAAAAAAAAAAP///////wAAAAD//wAAAAD/////AAAAAAAA//////////8AAAAAAAD/////AAAAAP//////////AAAAAAAA/////wAAAAAAAAAA////////AAD///////8AAAAA//8AAAAA/////wAAAAD//wAAAAD//wAAAAD//wAA//8AAAAA/////wAA/////wAA/////wAAAAAAAAAAAAAAAP////8AAAAA//8AAAAA/////////////wAAAAD//wAAAAAAAP////////////8AAP//AAAAAAAA//////////8AAAAA//8AAAAA/////wAAAAAAAP////8AAAAAAAAAAP////8AAAAA/////wAA/////wAA//8AAAAAAAD//////////wAAAAAAAAAA/////wAAAAD//wAAAAAAAP////8AAP///////wAAAAD/////AAD//wAAAAD/////AAAAAP//////////AAAAAAAAAAD//wAA//8AAAAA//////////8AAAAA/////wAA/////wAAAAAAAP///////wAAAAD/////AAAAAP////8AAP//AAAAAAAAAAAAAP////8AAAAA/////wAAAAAAAP///////wAAAAD//wAAAAAAAP////8AAAAA//8AAP////8AAP//AAAAAP///////wAAAAAAAP///////wAA//8AAAAA//8AAAAA////////////////AAAAAAAA//8AAP///////wAAAAD///////8AAAAAAAD/////AAD//wAAAAAAAP///////wAAAAD/////AAD///////8AAP///////wAA//8AAP////8AAP////8AAAAA//8AAP//////////AAAAAP////8AAAAAAAD///////////////8AAP///////wAAAAD//////////wAAAAAAAP//AAAAAP////8AAAAAAAD//////////wAA////////AAD//wAAAAAAAP///////wAAAAAAAAAAAAD/////AAAAAP//AAAAAP//AAAAAP////8AAP////8AAAAA/////wAAAAD//wAA/////wAA//8AAAAA/////wAAAAD//wAAAAD//wAAAAAAAP////8AAAAA/////wAA//////////8AAAAA//8AAAAA//8AAP///////wAAAAD///////8AAAAAAAD///////8AAP//AAAAAAAAAAD//wAA/////////////wAAAAAAAP//AAAAAP//AAAAAAAA/////wAAAAAAAP////8AAAAA/////wAAAAAAAAAAAAD///////8AAAAA//8AAP//AAAAAAAA//8AAAAA/////wAAAAAAAP////8AAAAA/////wAAAQAAAP////8AAAAA////////AAAAAAAAAAAAAAAA/////wAA/////wAAAAAAAP////8AAP//AAAAAAAAAAAAAP//AAAAAAAA//////////8AAAAAAAD/////AAAAAP////8AAAAA//8AAP////8AAP///////wAAAAD//wAA////////AAD//wAA/////wAAAAD//wAAAAD//wAA/////wAAAAD///////8AAAAA/////wAAAAD/////AAAAAP///////wAAAAAAAP//AAAAAP////8AAP//////////AAAAAAAA//////////8AAP///v8AAAAAAAAAAP////8AAP///////wAAAAAAAAAA/////wAA////////////////AAAAAP////8AAAAAAAD//////////wAAAAD/////AAAAAAAAAAD/////////////AAAAAP////8AAAAAAAD/////AAD//wAA/////wAAAAAAAAAA//////////8AAAAA/////wAAAAD/////AAAAAAAA////////AAD///////8AAP//AAD//wAAAAD//wAAAAD//wAAAAAAAP////8AAAAA//8AAP//////////AAAAAAAA////////////////AAAAAAAA//8AAAAAAAD//wAAAAD/////AAAAAP////8AAAAA//8AAAAAAAAAAAAA//8AAAAA//8AAAAA/////wAAAAAAAP//AAD/////AAAAAAAA//8AAAAAAAD///////8AAP//////////AAAAAAAAAAAAAP///////wAAAAD/////AAD//wAAAAAAAAAAAAAAAP//AAAAAP///////wAAAAD/////AAAAAP////8AAP//AAAAAP////8AAAAAAAD///////8AAP////8AAAAAAAAAAP//////////AAAAAAAA/////wAA//8AAP///////wAAAAD/////AAAAAP////8AAP////8AAAAA////////AAAAAAAAAAD//////////wAA/////wAA/////wAAAAAAAP//AAAAAAAAAAAAAP////8AAAAAAAAAAP////8AAP//AAD//wAAAAD///////8AAAAAAAD/////AAAAAAAA/////wAAAAAAAP////////////8AAAAA//8AAP//AAD/////AAD//wAA////////AAD//wAAAAAAAAAA/////wAAAAAAAP//AAAAAP//AAAAAAAA////////////////AQAAAP//AAAAAP////8AAAAA//8AAP//AAAAAP//////////AAD///////8AAAAAAAD///////8AAAAAAAAAAP//AAAAAP//////////AAAAAP////8AAAAA//////////8AAAAA//8AAAAAAAD///////8AAP//AAD/////AAD//wAAAAD///////8AAAAA//8AAP////8AAAAAAAD/////AAD//wAA//8AAAAAAAAAAP//////////AAAAAAAAAAD//////////wAAAAD/////AAD///////8AAAAA//8AAP//AAAAAAAAAAAAAP////8AAAAA////////AAAAAAAAAAD//wAAAAD//////////wAAAAAAAAAA//8AAP//AAAAAAAAAAD//////////wAAAAD//wAAAAD//wAA//8AAAAA//8AAAAA/////wAAAAD/////AAAAAP///////wAAAAD/////AAAAAP//AAAAAP7///8AAP////8AAAAAAAD//wAA////////AAAAAAAA////////AAAAAP///////wAAAAAAAP//AAD/////AAD/////AAD//wAA////////AAD/////AAAAAAAAAAAAAAAAAAAAAP//////////AAAAAP//AAAAAP//AAD/////AAD///////8AAAAA////////AAAAAP////8AAAAA////////AAAAAP//////////AAAAAAAAAAD//wAAAAD/////AAAAAAAAAAAAAP////8AAP//AAD/////AAAAAAAA//8AAAAA/////////////wAAAAAAAAAAAAD/////AAAAAP////8AAP//AAAAAP////8AAAAAAAD//wAAAAD//wAAAAAAAP////8AAP//AAAAAP///////wAA//////////8AAAAA//8AAAAA//8AAAAA////////AAABAAAA/////////////wAA//8AAAAAAAD/////AAAAAP//AAD/////AAAAAP///////wAAAAAAAP//AAAAAP//AAAAAAAAAAAAAAAAAAD///////8AAAAA/////wAAAAD/////AAD//wAA//8AAP///////wAA//8AAAAAAAD//wAA/////wAAAAAAAP///////wAAAAD///////8AAAAAAAAAAAAA/////wAA//////////8AAAAA//8AAAAA/////wAA/////wAA//8AAAAA////////////////AAAAAP//AAAAAP//AAD/////AAAAAP////8AAAAA/////wAAAAAAAAAA////////AAAAAP//AAAAAP//AAD//wAAAAD/////AAAAAAAA////////AAD/////AAAAAP///////wAAAAD/////AAAAAP///////wAA//8AAAAA////////AAD//wAAAAAAAAAA//8AAP///////wAAAAAAAAAAAAAAAP////8AAAAA/////wAA//8AAAAAAAD//wAAAAAAAAAAAAD/////////////AAAAAP//AAAAAAAA//////////8AAP///////////////wAAAAD/////AAAAAAAAAAAAAP////////////8AAP////8AAP////8AAP//AAAAAAAAAAAAAP///////wAAAAD/////AAAAAAAAAAD//////////wAA/////wAAAAAAAP///////wAA/////wAA////////AAAAAAAAAAD///////8AAAAA//8AAAAAAAD/////AAABAAAA////////AAAAAAAAAAD//wAAAAD///////8AAAAA/////wAA//////////////////8AAAAA////////AAD//wAAAAAAAP////8AAAAAAAAAAP//AAAAAP////8AAP//AAAAAP//AAAAAAAAAAD/////AAAAAAAA/////wAA/////wAAAAAAAAAA////////AAD/////AAAAAAAA/////////////wAAAAAAAAAA//////////8AAP//AAD///////8AAAAAAAD///////8AAAAA//8AAP//AAAAAAAA/////wAAAAAAAAAAAAD/////AAD//wAAAAD//////////wAA////////AAAAAP////8AAP///////wAA//8AAAAA//8AAAAAAAD///////8AAP////8AAP//AAAAAP//AAD/////AAD/////AAAAAAAAAAAAAAAA////////AAAAAP//AAAAAP//AAD///////////////8AAAAA/////wAAAAAAAAAA/////wAAAAD///////8AAP//AAAAAP//AAAAAAAA/////wAA//8AAAAA/////////////wAAAAD//wAAAAD/////AAAAAP////8AAP///////wAAAAD/////////////AAAAAAAA/////wAAAAD///////8AAAAA//8AAAAA//8AAP////8AAAAA///+/wAAAAD//wAAAAD/////AAAAAP//////////AAD/////AAD/////AAAAAP///////wAA//8AAAAA//8AAP//////////AAAAAP//AAAAAP//AAAAAP//AAAAAAAAAAD///////8AAP//AAD/////";
    private static final String NOTIFY_WAV_PART2 = "AAAAAP//AAD//wAA/////wAA/////wAA//8AAAAAAAD/////AAAAAAAA//8AAP////8AAAAA////////AAAAAAAA//8AAP//AAAAAAAA//8AAAAAAAD//////////wAA/////wAAAAD/////AAAAAP////8AAAAAAAD/////AAAAAP///////wAA/////wAA/////wAA/////wAA/////wAA//8AAAAA//8AAAAA/////wAAAAD//wAAAAAAAP////8AAAAA//////////8AAP////8AAAAA//////////8AAAAA//8AAAAA/////wAAAAD/////AAD//////////wAAAAAAAAAA////////AAD//wAAAAAAAAAA/////wAA//8AAAAAAAAAAAAA////////AAAAAP///////wAAAAAAAP//AAD/////AAAAAAAA//////////////////////////8AAP//AAAAAAAA//8AAAAA/////////////wAA//8AAP//AAD///////8AAAAA/////wAAAAAAAP//AAD//wAA////////AAAAAAAAAAAAAP////8AAAAA//8AAAAAAAD/////AAD//wAA//8AAP//////////AQAAAP///////wAAAAAAAP///////wAAAAD//wAA/////wAAAAAAAP///////wAAAAAAAAAAAAAAAAAA//8AAAAAAAD///////8AAAAA/////wAA//8AAAAAAAD/////AAD//wAA/////wAAAAD/////////////////////AAAAAAAA/////wAA/////wAAAAAAAP////8AAP//AAAAAP//AAAAAP////8AAAAA//8AAP//AAAAAAAA//////////8AAAAA////////AAD//wAA//8AAAAAAAAAAP//AAAAAAAAAAAAAAAA/////wAAAAD//wAAAAAAAP///v8AAAAA//8AAAAA/////wAAAAAAAP////8AAP//AAAAAAEAAAD/////AAAAAP////8AAP//AAAAAAAAAAD//////////wAAAAAAAP///////wAA/////wAAAAAAAP//AAD/////AAAAAP//AAAAAAAAAAD//wAAAAAAAP//AAAAAP//AAD/////AAD//wAAAAAAAP////8AAAAA//8AAP//AAD/////AAAAAAAA//8AAP////8AAAAA/////wAAAAAAAP////8AAAAAAAD/////AAAAAAAAAAD/////AAAAAP////8AAP////8AAP//////////////////AAAAAP///////////////wAA//////////8AAAAAAAD//wAA/////wAA/////wAAAAD/////AAD//////////wAAAAAAAP////8AAP//AAAAAP////8AAP//AAAAAAAAAAD/////AAD/////AAAAAP//AAAAAP////8AAP////8AAP//AAD//wAAAAAAAAAA//8AAP////8AAP//AAAAAP//////////AAAAAP//AAAAAAAA/////wAA//8AAAAA//////////8AAAAA//8AAP////8AAAAA//////////8AAAAA/////wAAAAD///////8AAAAAAAD//wAAAAD///////8AAAAAAAD///////8AAAAA////////AAAAAAAA//8AAP///////wAAAAAAAP////8AAP//AAD//wAAAAD/////AAAAAP//////////AAAAAAAAAAD//////////wAAAAD//wAA//8AAAAAAAAAAP//AAAAAAAA/////wAAAAD//wAA////////AAD///////8AAAAA/////wAAAAD/////AAAAAAAA////////AAAAAP//AAAAAP///////wAA/////wAA//8AAP//AAAAAP//AAAAAP///////wAAAAAAAAAA//8AAAAAAAD//wAAAAD///////8AAP////8AAAAAAAD//////////////////wAAAAAAAP////8AAP////8AAAAAAAAAAP//AAAAAP//AAD/////AAAAAP//AAAAAAAA/////wAA/////wAAAAAAAAAAAAD/////AAD/////AAD//wAAAAAAAP///////wAAAAAAAP///////wAA/////wAAAAD//wAAAAAAAP////////////8AAP////8AAP///////wAA//8AAAAAAAD///////8AAAAAAAD/////AAAAAP//AAD/////AAAAAP////8AAAAAAAD///////8AAAAAAAD///////8AAP////8AAAAA/////wAAAAD//wAA////////AAAAAP//AAAAAAAAAAD/////AAAAAP////8AAP//AAD//wAA//8AAP//AAAAAP////8AAP///////wAAAAAAAP//////////AAAAAP//AAD/////AAAAAAAAAAD///////8AAAAA//8AAAAAAAD///////8AAAAAAAAAAAAAAAD//wAAAAAAAP///////wAAAAD//////////wAAAAAAAP////8AAAAAAAD///////8AAAAA/////wAA//8AAAAAAAAAAP///////wAAAAD//wAAAAAAAP///////wAAAAAAAAAA//8AAP////8AAP///////wAAAAD/////AAAAAAAAAAAAAP///////////////wAAAAAAAP////8AAP//////////AAAAAAAAAAAAAP///////wAAAAAAAP////8AAAAA//8AAP//AAD///////8AAAAA//8AAP///////wAAAAAAAAAA/////wAAAAAAAAAAAAD//wAAAAD//wAAAAD//wAA////////AAAAAAAA/////wAAAAAAAAAA//8AAP//AAAAAAAA/////wAAAAD/////AAAAAAAA/////wAAAAD///////8AAAAAAAD///////8AAAAA/////wAA/////wAAAAD//wAAAAD/////AAAAAAAAAAD///////8AAAAA//8AAP///////wAAAAD/////AAAAAP//AAAAAAAAAAD/////////////AAAAAAAA//////7///8AAAAAAAAAAP//////////AAAAAAAAAAAAAAAA/////wAAAAAAAP///////wAAAAD//wAAAAD//wAAAAD/////AAAAAAAAAAD//wAAAAAAAAAA//////////8AAP////8AAAAAAAD///////8AAP//AAD/////////////AAAAAAAAAAD/////AAD//wAAAAD//wAAAAD//wAA/////wAAAAAAAAAAAAAAAAAA////////AAAAAAAA//////////8AAAAAAAD//wAAAAD//wAAAAAAAAAAAAAAAP//AAAAAAAA/////////////wAAAAD///////8AAP////8AAAAA/////wAAAAD//wAAAAD//wAAAAAAAP////8AAAAAAAAAAAAA/////wAA//////////8AAP//AAAAAP//AAD//wAAAAD/////AAAAAP////8AAAAAAAD//wAAAAAAAP///////wAA//8AAAAA//8AAP////8AAP///////wAAAAD//wAAAAD//////////wAA////////AAD//wAA/////wAAAAD/////AAD//wAAAAAAAP////8AAAAA////////AAD/////AAAAAAAAAAD//wAAAAAAAP////8AAAAA/////wAAAAAAAP//AAAAAP////8AAAAA//8AAAAA//8AAP//AAAAAP//AAAAAP//AAAAAAAAAAAAAP//////////AAAAAAAA//////////8AAP///////wAA/////wAA//8AAAAA//////////8AAAAAAAAAAP//AAAAAP///////wAAAAD/////AAAAAP////8AAAAAAAAAAP///////wAAAAAAAAAAAAD//wAA//8AAAAA//8AAAAA/////////////wAAAAD//wAAAAD/////AAAAAAAAAAD///////8AAAAAAAD//wAAAQD/////////////AAAAAP///////wAAAAD/////AAAAAAAA//8AAP////8AAAAA/////wAAAAD/////AAD//wAA//8AAP///////wAAAAD//wAAAAAAAAAA/////wAA/////wAAAAD/////AAAAAP//AAD/////AAD//wAAAAAAAP////8AAP//AAAAAP//////////AAD//wAA////////AAAAAP//AAD//wAAAAD/////AAAAAP//AAAAAP///////wAAAAAAAAAAAAAAAP///////////////wAA/////wAAAAD///////8AAAAAAAAAAP////8AAAAA////////AAAAAAAAAAD//wAA//8AAP///////wAAAAAAAP//AAAAAAAA//8AAAAAAAD/////AAAAAAAAAAD/////AAAAAP//AAAAAP//////////AAAAAAAA////////AAAAAP///////wAAAAD///////8AAAAA////////AAAAAP//AAAAAAAA/////wAAAAD//wAAAAAAAP////8AAAAAAAD///////8AAP//AAAAAAAA/////wAA////////AAAAAP//AAD///////8AAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAD//wAA//////////8BAAAA//8AAAAAAAAAAP////8AAAAA//8AAP//////////AAAAAAAAAAD/////AAAAAP//AAAAAP///////wAAAAD//wAA////////AAD///////8AAAAA/////wAA/////wAAAAD/////AAD/////AAAAAP//AAAAAP///////wAA/////wAA//////////8AAP//AAD/////AAAAAP//AAD//wAA////////////////AAAAAP//AAD//wAA////////AAD//wAAAAD//wAAAAAAAAAAAAD/////AAAAAAAA////////AAD///////8AAAAAAAD/////AAAAAP//AAAAAAAAAAAAAP//AAAAAAAA////////AAAAAAAAAAAAAP7///8AAAAA//8AAAAAAAD/////AAD///////8AAAAAAAAAAAAAAAAAAAAA/////wAAAAD//wAA//////////////////8AAAAA////////AAD//wAAAAD//////////wAAAAAAAP////8AAAAAAAD//wAA/////wAAAAD///////8AAAAAAAD/////////////AAAAAP///////wAAAAAAAAAAAAD//////////wAAAAD//////////wAAAAD//wAAAAAAAP///////wAAAAAAAAAAAAAAAAAAAAD///////8AAAAA//8AAP////8AAP////8AAP//AAD/////AAD///////8AAAAA////////AAD/////AAAAAP//AAD//////////wAAAAAAAAAA//8AAAAAAAAAAAAA//8AAP////8AAAAA/////wAA/////wAAAAAAAP//////////AAD//////////wAAAAAAAAAA////////AAAAAP///////wAA//8AAP///////wAAAAD/////////////AAAAAAAA////////AAAAAP////8AAAAAAAD//wAA////////AAAAAAAAAAD/////AAAAAAAA////////AAD//wAA//8AAAAAAAAAAAAAAAD///////8AAAAAAAD/////AAD/////AAD//wAAAAD//wAAAAAAAAAA////////AAAAAAAAAAD//wAA//8AAP//AAD//wAAAAAAAP///////wAAAAD//wAAAAAAAAAA//8AAP///////wAA/////wAAAAAAAP////8AAP////8AAP////8AAAAAAAD///////8AAAAAAAD//wAAAAD/////AAAAAAAA//8AAP////8AAAAA//8AAAAAAAAAAP//////////AAD//wAAAAAAAP///////wAAAAD//wAAAAD///////8AAAAAAAAAAAAA//8AAAAAAAAAAP////////////8AAP//AAD//wAAAAD/////AAAAAAAA/////wAAAAD/////AAAAAP////8AAAAA////////AAAAAAAA/////wAAAAD///////8AAP//AAD/////AAAAAAAAAAAAAAAA/////wAAAAD//wAA/////wAAAAAAAP//AAD///////8AAAAA//8AAAAAAAD///////8AAP//AAAAAP////////////8AAAAA/////wAA//8AAAAA/////wAA//////////8AAAAA//8AAP////////////8AAAAAAAAAAP///////wAA//////////8AAAAA////////AAAAAAAA///+////AAAAAAAAAAD//wAAAAD//wAAAAAAAP///////wAAAAAAAAAAAAD//////////wAAAAD//wAAAAAAAP//AAD///7/AAAAAP///////wAAAAAAAAAAAAD///////////////8AAAEAAAD//////////wAAAAD//wAAAAD//wAA/////wAA////////AAAAAP//AAD///////8AAAAA//8AAAAAAAAAAP////8AAP////////////8AAAAA/////////////wAAAAAAAAAA//8AAAAA////////AAAAAP////8AAP//AAAAAAAAAAAAAP//AAAAAAAAAAD/////AAAAAAAAAAAAAP////8AAP////8AAAAAAAD/////AAAAAAAA////////AAAAAP//////////AAAAAP////8AAAAA////////AAAAAP///////wAAAAD/////AAD/////AAAAAP//AAD//wAA//8AAAAAAAD/////////////AAAAAAAA/////wAAAAD//wAAAAD/////AAAAAAAAAAD/////AAAAAAAA/////wAAAAD///////8AAAAA/////wAA/////wAAAAAAAP////8AAAAAAAAAAP///////wAAAAD/////AAAAAP////8AAAAA//8AAP////8AAAAA/////wAA//////////8AAAAAAAD//wAAAAD/////AAAAAP////8AAP////8AAAAA//8AAAAA////////AAAAAP//AAAAAAAA//////////8AAP///////wAA//8AAP//AAAAAAAAAAD//wAAAAD///////8AAAAA//8AAAAAAAAAAAAA////////AAAAAAAA//8AAP////8AAAAA/////wAA//8AAAAA//8AAAAAAAAAAP///////wAAAAAAAAAAAAD///////8AAP//AAD//wAA/////wAA//8AAP//AAD/////AAAAAAAA////////AAAAAP//////////////////AAAAAP//AAAAAP////8AAAAA//8AAP////8AAAAA////////AAAAAP////8AAAAA//8AAAAA//8AAP////8AAP////8AAP///////wAAAAD/////AAAAAP//AAD/////AAD/////AAD//wAAAAD/////AAAAAP///////wAA//8AAAAAAAD/////AAD//wAAAAAAAAAA/////wAAAAAAAP////8AAAAAAAAAAAAAAAD/////AAAAAP////8AAAAA//8AAAAA//8AAAAAAAD/////AAD//wAA/////wAAAAD//wAAAAAAAAAAAAAAAAAA/////wAAAAAAAP////////////8AAAAA/////wAAAAAAAAAA//8AAAAAAAD/////AAAAAAAAAAD//////////wAAAAD/////AAAAAP//////////AAAAAP//////////AAAAAAAAAAD///////8AAAAA/////wAAAAD/////AAAAAP////8AAP////////////8AAAAAAAAAAP//AAD/////AAAAAP//AAD//////////wAAAAAAAAAA/////wAAAAAAAP//////////////////AAAAAP///////wAA//8AAP///////wAAAAD//////////wAAAAD///////////////8AAAAA////////AAAAAAAAAAD//////////wAAAAD//wAAAAD/////////////AAD/////AQD/////AAAAAAAAAAD///////8AAP//////////AAD/////AAD//wAAAAD//wAAAQAAAP///////wAAAAAAAP//AAAAAAAA/////////////wAAAAAAAAAAAAD//////////wAA/////wAAAAAAAP//AAAAAP////8AAP//AAAAAP//AAAAAP///////wAA//8AAP////8AAAAA/////wAA//8AAP////8AAAAAAAD//wAAAAAAAP//////////AAAAAP//AAAAAP////////////8AAAAA/////wAA////////AAAAAAAAAAD///////8AAAAA//////////8AAAAA/////wAA//8AAAAA/////////////wAAAAAAAAAA//8AAAAA//8AAAAAAAAAAAAAAAAAAP///////wAAAAAAAAAAAAD///////8AAP//AAD//////////wAAAAAAAAAA//8AAAAA/////wAA//8AAP//AAD/////AAAAAP//AAAAAP//AAD/////AAD///////8AAP///////wAAAAAAAAAA//8AAP////8AAP///////wAAAAD/////AAD/////AAAAAAAA//8AAAAAAAD/////AAD//wAA//8AAAAA////////AAD/////AAA=";
    private static final String NOTIFY_WAV_B64 = NOTIFY_WAV_PART1 + new String(NOTIFY_WAV_PART2);

    private static final String TEXTURES_JS_PART1 = "const ORE_TEXTURES = {\n    \"coal_ore\": \"data:image/png;base64,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\",\n    \"iron_ore\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEUAAABLCAYAAAAmh0pZAAAbLUlEQVR4nNVcSY9c13X+7htr7IndTYoiqYmyJfgnZOlx4V12AQx4YVgwYEObxDAELWQbsA1okSwCBFk4ezs2YEM/IKv8gDhANIvm1CR7qq7xze8G33nvVN8q0rZkU6b8iEKzq95w73fP+c53zrnVwGfguHHjhnV/PunDe5IPv3PnjoDwy1/+Eq+99pr9xS9+Ie/funXriYJjnsRDb9++ba9evWp+9rOf2bOzM1hr5ZXnOeq6xs7ODt544w1z8+ZN+8wzz/zVx2ieJBhlWaKqKgRBAM9rjPazAI55EmAYY2TS4/FYAAjDEIPBAMPhEFEUoSgKJEmCNE2fCDif6gNutpP46U9/agkAwaBVcOL8/3w+x2QyEevwfV/e73a76HQ6MMZDWT4aHAX50xr3p3Lju3fv2qefftq88cYbdjQaiWtwor1eTybPg26TZZlYBf9PV+LEeXTiEBc2BjBBhNIaOYfA8Bzea3t7Gz/4wQ+MPudxj/+x3vC2s4I/+tGPLCfCldbJ0AoIDK1FuYPn8ODvBMVHhWsbPi72A2TWx0EaIEMo1xM8AkQro8u9/vrr8qyDgwN7+fLlxzYX87g5YzKdIgwCGTQnQkDUBWglBCSk+wDyPq2F7+vLM8BmBGwEFSZpiaOFBfxg6VZKyO7x2muvyTweF+eYx0mgcWBgLZCVNTxyRBjKqnJ1CU4UeAh9D4u8RFVb1GtuI6B4ngCYZxlgPMRxvAQiisKHwOG15CZyVr/fx5tvvmmof65cufJnz808DjBgLa5txXhxr4vKWnx0kuJgnKFo5gpYYG+ji398/Q3z3//57/bW0QQfPRhjmhaoBBCL0FgssgJlZVFWJaqyQhxHAgCPADWyspTPScgEgAcBIYh0Lb6/ubmJH//4xzKvPxecT3TBzdY8XdElWqMssTeM8Lm9Pra7HrI8x2hR4mBW43BeoagqbHRCvHTlAp7dG6JjSkznCW6epjhNazyzv439zS4OTqd49/YRjqeJWBJdMI4CPH+hh+d2OpilBd57MMVZbtDpDQTM2Wwm42BID1vLJEDkKwJHQqZCvnbt2seeq/kkYHz/+9+3HARNmNzAQyNHVdXwPWCr4+PSwIetK/z+JMHJohQO4fkGFlvdCM/tdnFlswNbFeJqGxsbMinPVpjNF7h5MsPb96YYpyUCz+DKVhfX9/ro+RXOpnNMCoMJehhnFrP5XEAhAOpqdCmCotGN9/8kOsd8HDf5yU9+Yu/fvy9myslpaNUowBeBoSnTSnzTgJXmhfDK1taWmPYiSZAsEnnoIPZwsc8o46MTekLOnSiEF/i4eZrhnQczzLNSxsFEKPINNiODXXqT5+GkCDDNIZMmKGJVcbwcD8fGMS0WC3nx+Lgi0Hzc3KRoyVIjCFfkUaBwhRhBeGu6AMlRrMDzJNrwxfvpw/uRh0uDAHt9H6GpkRUV7s0qPFgAlWmexZXn82tbwzemiVRBKPfg+zx0TM3LRxyHcu7JaIzZbCrXKFh/ChzzRwkUZPxIbkhTJOK0AON5CDSEtuCIhshzbMQGTw8DGAMcTCuMkkpWWlbc2qWqVd1RVpUQdS9srGArNkhqH0eZj9w2EUafzeu7nY6Qb6fblUiXJAtZCFXFvPdGN8T13S56AfDuwUjc0QQxOnEsAPO5ruWsc45xwfjhD39op9PpcqL8SZPkg+g65JOyrMTPa46onSAHw0FVVYmd2ODaZogwCnFShDheVJgvUuR51oDieeJSURCgZFiWQZawthksQ7bnBzB+AM8wxFskSYoiT3B5Z4gvPPsU/v6VfzL/9i9v2nHCaFULaLRABWd3EOMLTw1xcRghzTLcHyc4TICTFKhsE8aVCzn+3d1d0ToarczZ2Zn9+c9/jrffflsA8NvVX4qpVg/IA+sKT292cG2ni7OkwI3jOWZZJeAQXQ5IlGscohN34IuVNepVV9u3FV7Y6+HCoIN70wKnSYWndwYSsu8cT3DjwQjTOXOdJsT2uh3sdH3sdYGre1vY3dlB4DNvWuDBNMOdWY1J1pQeVEFnWY7AA3Z6AS71fQxjD6Pc4GBukTdGsszQNe1gOvLcc8/hu9/9LgKidnp6ipOTk2W22u12l2gqOGL2voedfoiLwxh7PQ895LhzVuM4tSA2PMQtrEGSF/BoVW0CyHsHYYguDHYHEfYHAXpegb2oxqWdCFubA1zdjPHsZoD/u3OMjw6nssok7agbox/4mI5HmE3G6MURBr0YPQPUyRzTWS3upMJOwTmc5TiZl4hDD7UJxEo5D7d+Q5o4Pj6WxJRj5LwlruqJJMr5fC43ZxhTcIiqrLa1+J87E/z+eI6d2GIjstjp+ciNh7OM7nOuUBVMvV61w6ws8V9vz7EVQ4Dd7Hg4uJtidHqMjV4XW90YL13dh403cDRZiIXdGOU4nJNzDLYiC7pNNgNOEovjcZNbMbJp0umCIxGPETGoETr8R8u4c+eOGIQAQclAIhSh6LJue8F8PhekXXBUqNESTuoAZ4lBJzAwvoH1yOxNVOD1mrjxJyOBH/hCzLRCvkdJfucsxfE8wN4wxn6vwrBk6EzgBRFO6g4qL5ZQzvvQ7ZI0xc1JjcOAwi1E2AnhRz62t8OlZXDc5ERaJsfNn8I3bdTks4+OjpjFCxiaXCrp88V5roCibmLbjJXEyocRdfKN+Hivh+FgIETLwdiygOc1bqLsr9fzxXzo2lYHW4MeTnMP8wLo9npI2yTxLK+QexH2gggbtkCUU3xkWGQhbNisOKU7n0twBIDJHMEik/f4OcHmT46XgBMYTpBj1jkcHh6KdfBzF4zzINH6/6MsxW/juYZC1R+8MVUjw5jqjqzTWWa6ok+cJE2PvUGEz+33sd2LkZsQf/cPr5p//ec37YQAhiHyLJcJJX6Awlh4dY5RmmCeZKT3pcU+ChxOnhPk58qHaulcQCXf27dvC3eInHDAUHfRAKFRdwUUt1YRkhiDQN7jhNWMb968KQ/Y399f5htuUqZCigd/vzdOEaLCy5e3sLvbx/++9R92lqS4eTjGjeMStWcxDEpc2ggxKTyMsy76wxhBnIk1KeAKDlefrkFw+L4o5zRdjpNA8Sctgi+6Ce+hglHDsAKixqCvhyxFVatrNRo59DPlBE24ODh+zvPUQlyLYV1k4Jc4Oj7GdDbD5nCAfhzi+U0P22EHp/McFzc66Mc+ZlmJW6MEpzaA34lF+nMMnDQnpitNq9FxKX9pMODC0VXUgoUjWrHI84p2fpHfiLRGUayK2hVQVjSJbfIJVbQ6CE5UOYOrQp/VvIOFZ437er8EPh5UHnb8GmWaYZEco0AA64cYhhDVmSwqZKmPeZIgLAps2RCndoBF0VieugKfwZemHTz4bP5OSfHee+8JkepYXRHKg8AN4gCbvQBxAKRFA4oq7UeCQncoy3LZYmhMt8BmP5LB5LUH40yaB29IYMjoNOvLly+LmetDqE5JmGcsVKNElS9wNEmRlTmGcYDLGyF2u0DsN1ZgTYAZeqhMiA4jjO8vIxlfmjtp+OezaRnUGnRrIfc4lme7C8T3t3shLvQ6zdwKLXTVkoa45z4UfaLWMtRfmYSFtsCFABhlHqbVuZhbD+V0K41QBIavhqhnYsIcrIk20BtGTFrAtb49NzjJLHZiYOhXUqPt1jNM8gJ10BAoV5riipNRl2EkIRh8prq8WoY7NgWwZnIa+wh4r7zC2aLCorBSFNNywyNDsjtJv5X4rIwJkrAwdY75vBmYgqeD0Iilfs1V00I1z+W9+FNdwXcGMqs9LEqDbhBiIwoxmueYpDN4fir8wfuRzNWKCYj2j/SlEUQJtQGi4Th9Ly1q3C8yEX/Mu9YpQ8EN3Itci6lbnUHRtaiABwlQVo0ZavFGwdFr3BXieVxdDp4TI99oxNAV1WcoYAj7SIIIwaBEP2iiGT/nuXSTe/fuyU/lCY1y7mJqHaURjk2YFQ60VqqBOle93o2wK9FHV8yV58aYJeOzqHOWMTo1TK81DuEcguNkyjo47fTxHBVQrkLWAesC8Dz+1ApaNBxK1Dk4OBAZoAqU13Ax1nWGSnUtc+hYFPh1MNxkV8sZWm9ZgqJVqrhVrnoBB6JA8b66AhIFCKYAysn0VlZWH8qX6hw3faCEpxhTgPW+Wkakld26dUt4Q1dRV3ZdeatlNJ1FSdqXi+TKhHUwtGwpJYsWkKWlKJnxpKRtXmnoc/3TDV08f9ANsRkbjJJaMlCOZj5rSFXbEASYv3OSKu5U7NGCqJBpHTyPzyUITNQYYvn7HwLjvDbMYGCl9uKjRoQatWeks6hAPwoM7VBqNdG1qEDFEMMxUctbjaK1T71AAdI+sFzsGTy91cFuv8LhNMe0bPyX9xDE28k00akpKTar2QyYfMNFoEvxORpaOdhHgcHlMKil9suKnY6pF/rY6AZSq2EdJmVYaEWbCwZNne7uLvK6Na+EZF5Ms46iaAmMDmyZMPFnbcF/RVEiyYF5HiL2gC6YqwBz30PB2K/tD6nJeFKcrkr2t5oitctjFIF8MbzqQF0fl8nbGr2ghrE15lKpa7ggDHw8tRmhE3iYLirkNQMC3bpZUEY5Ll4/AuZJgXk7cfcZHKdapYCiK6tm5Lcv/t7vUMFaJDk/C3BhEKMb+rh/NpPG1TQppBWx3Q0QM2S3XGJNk4qrICL3XN8fIC86OKJ6rc81hWu2Gj109dR1ORYWtePQR9EWiDgutk44aekqlrW0POZ5oz2EFnyD7X6Enk/tQXc5J1V3T4yOW616SbQaKgMnzO0Pm7Lh/bMpDieJlBlf2N+UXOXgdIzDSYaE1fciR0hrCTxUILGthlu2LaLAl4ZZP0oxSkqMUiCvz/nBzaxdv1dB5QdGrICCi3ViTpvrSj45mmVIsgp55egSa7HZCbHTi1CVOUq2K9mG7XQESD3PpQUFaSXQM5LULR/wVLoJyfQZr4/tGCBNssjciwM8e6Envvze4UxMlc8sckYeu2IFksXWNe6N2e+J4RsrDfSkBLL8vOrnhlBN7tyVrNHIAmolVVXN/S2y/FwKaO+6sbzmnDRrdjfUNd2pyd/cSKnXPgQKP+uHHvLKoqisrML90Uy6ehd6Afox26EFRqNTxEy4fEgB2Tg35KrRVbRjpwqUA3gwyTBaFNiIPWyShOx5FHPDoYLiJnPyGYFp0Vi2VTgpZ1HVXZWUy6LAbF40uZNYLvmuyajVit1+kV5/DgqAi8NQCOvBJMdZWmGa5pjcTSWzvLgRYRAZVCVvSu3iyaqxVUoOFpZnUcchMk3xNaplZYXjspZSJk3YGkaG86KPOzmVCXqoNelkeMSBh34cYJI2jXkFpJkoQaP7AWUNJAUwJ6G2yCqPrESnR1beAGx2fPi1J33b+1OLSVljkhSYpSW6kcFW7GGjw5vU8GqLSz2DSQ4sbOMGssqGFbcYi6KWwayDw3Ba1BU8c65CdeIEQ3caaC6yrkrjMMBWL5bGG42IdRi6pWYZEsLlOotpbjHParF+u0aqSyt0OGwFFAJ4MGa+UaPrW6lzsGLGSbCzxpnOc06yxig12O74GEYGgk9kkOaEqXUlAJc2OjCewdF4LlaX42HLURJ1DzVlle0ux/Bgv/nq7ga6kY8qT5GXFfoB4AUGC4Zj4Vhu56gwKhsgNHwHjwDDdVkl+xVLmSQlJosCvcjDdof9myacElkmc1r2YwRIyxIj34BVAOoAnRDP80jRdYVuFOFS38MwqHHjLEdOovNXwXEnvA6OWo8LFjUOI5lEzLIUvdQLGIbFeJd9Z7dnFQSrYKhFCwBrSeVDoMh2rKrCNKuwyLmK59mvCh2p47bOtigtkgqiIeA1PWYZhAdMJmeoyy4CY6X0V+UZpmklVqdlB4JD0ebWd91DeUQH3oRhdhsT4Ta9hpF4UUKsRgpHtDJJMUJpxK+DoaLSLXf8QVDWcwvbxm/VMW5y5eYLec1ay7ki9KKgrYpNxa8bVdysotZO3bquliJc/1YOsY4QG0S+kH3R9qUJAK12nlHzNK5CMDYGHWx1A2nUEywXDJeb9P11jSSgqO5XEwtbBHWbJi9iBu36oev7MmPblPiYW5SFj1EYywYey8SrqBCEMbq2qehpT8nNpnWQqjF0kXzPNKTaDRGAY6kwIxB5La+CYLScwfMuDLqIfY6pRpbUCFHKtrCMyq9V3W47QwFR5SyWqQPhCup2TtO6i6JLzpCygVPJ0gyULsOtW1cvDPBgNMPdo5EM4v7MxzirMQwNeoGRjYHdbuM6Cgx/8jlMRt1OggJCaLpRgN2NrvBUmuYYJyXOFqXoKbV60Ru+j93NvoToIkuRseRRleigktSAjqfyXkHQa7Wlu4w+rpJzSwVmqTQZpj0RXceLGrP8PNljq2LYDeD5Hrb7Xez0Y+z2PNwdzaWcQNNOCovYNwjjEn7YuJ02r3TPiVshc7WDKE4JzTWmSYrTaYKUEt8B41zkiXxtOoiLRbPqLfex2N7h1g6nl+xa6XprRmAj4bkV+MpNrX1PdgQRFPgRbNpU5Mj6JNDndmJZtSSZoxt3sDOIJQ1496TAPGF0KZBxD0mSIuB2L92BwM01GxtLohXeaJtwOlDhoKLEzaMx0qIUxawO7KpduhjVeJosUFeN+xG4Ej4KE4jCpHIhSbMwHngWhbfaEHO3hS13HbgptOesAEPgoqoxSWtYv7lY6poi0hoyjj2L09EpZkGIbhzABKFc1+uxqd24i9tM4++6P01bm25rwq2YFWWjIWTgTlPrfIuYxX4/RC/0ME9ScXH2ctLSkJ3b4AF0aa22hK1yad9WkrRWyAl2q4keGX3cxri33D/GtBy4NS7QiY10+qWixvBcGrx/uMBOx4NlDaPKmo2ADMs2Qsk9Ia1iVS5xucM1WxVyy8i3DJPNe1r3dRthTf2Ycp/QQGTEOK1QcluY4fvNnMhrW11aOJBWzZ5cDznyqhRZsbS49dyHh5YEqzZld/MMiqO0qBBSm7aJFM35ZJ7jZFojMpVEm2HMqlfJdhYC+BiXoWwjVznvFrG0UE6CZzSSXQwEhkRrgI7PIGJxmjb1nHXAmhKBEdE5zytMFsxtaoRBQ7wCIOtEcbD8ChzFIylcLLYl9PUK3UOgxHG83D/GSXOruJuJrtc/mNhx8/AkqyREbvaM1G37IcRcMyZrYCOsqdXqANx6iRseeT9uJ2XEMrbEguWFtS9HqcsrKR/NmyxYdFXbwtX9KAzN3E+XFXVTy217WUwHao/t0/MMXcF+yH18p3XANiPPm6YNyblpvaLqNsRo1tQQWe3hQtBFBMZ9JoBUn023XwvZ6zud9JkEhBxBf5/nFGVN69WNGi646k4sXMftpmctHXBbVz/yEZkaRVuYYsa8KEgJTQuYQUQX+qGEUEiNe1XrVklyS2UvxMXNDu6NFrg/TpHV51bicg4Jk/UT6eq3eUeGAIUXIeqGqNuqufIJB85opyarOzCFX9pq2iTldlMKLy1TsrJn0Il85Igow5YLudxX0pYMOoEvUqFjatnFnebc12+bwlZ9XpcxTrHJ7S4uy5H6QekwPXmEO513ez68kjsMgTGz4bXKleQyrIswokQs/zXKUNQhAWuFoLYUtLuoluJmrSxv3j5jUXw1g+Y4uNuRYBQlOa5xbR0DL499iHQYdGmNPso8Ewvhdnbu52U5kqApn+kYH1lPcUOx37qDtBym7LnWGDShXgpQC8tI0YAoL9ZAUOJS32CaM0mU1FO+mkKght1IarGmDeWaabuaSK2rAaUBXFde3bLhFa40yZOJ33m+0og8ljlD9KOmdMHdEmmSSjRcsJgt1f3VKKvc9ND+FGlqDQYrBOq14FB03R0VTTIWEuhGLi+b7+2Oad6SO6W533VehzieFzhm67KupQjFIR/NKyTVeZXN7fK7VqfhV8WUgMaIaIHThPK+4RiX9JuGPWFpOg9lnaNSKqBLGmbMzWK7yZ8uvoLCfrdYLX/56KOP7PPPP2+++c1vWjak3E6ga8IkMy0P6ANkz1no4cX9Abb6MeLuUPo+R6MznC4KXNmMhAtOxvz2BTApfKTM9deeoX0ftwNJS1kmarSqlpCXTXNnglT5LDwVpcUgZGrBQrsnG4SKZs/EypZWt0b71FNP4be//a15//337YsvvrhqNx988IG9fv36Cjg66PXquvKAchC/9bU/jPHs/jY6cYQymyNvG/LUBvx+D7PlKbpI6oa73H4P26ouKGrW7nYKN2F0V3s5zhacjYibf3xUlPhe4zNu8UmfeeXKFbz11lvmnXfesS+99NLq3vz144M1cPRmK/F/7RCN4AHPboYY9rsSDmnS3PSnrQha0MSyl3i+rZTky0MtRSe6cu+HVO7qwrgTFfcUVzrnJLeWwt+52+rLX/4yvva1r8EF44+Csg7ON77xDcvtWwyj9Du3xsqjGYyPwNS43Gfq3Zh/FAVSMJbfmcRaVtQN5pbUzEjCCt1kufuRoLj1nHUwOFhOmFtDGEl08Ms6yCN2PbqfKxhf/epX8fLLL3+y7/usH+pr3/rWt6zuOTvfE6fN9BCesegHFgO/RuQ1ddMHCyutCG5X7/hcNVbyLU4L7pttyge6U0k3FWrBemW/i2+koC7WV/kCsJurNWNYBUWvvXjxIr74xS/+STCW1+ATHB9++KF94YUXzKuvvmq5O4AroBnuykY6+nXHl71y92clssqix9pL1LROmJAdLiymhQRacU9ajHzLY22jISMfv6rCLe8M81S444K1ZPLcKnBuJOFPJdB1znisoOih0ep73/ueuNV6jVO3d9BysqwQrbD0d0nja9l/xlyJIovv03X0S5IuuQ46Aa5ud5vNf7NUGujUYS4Yyi36+nPBWI4ff8HxUQvOK6+8shKtODD3+8Tqai5Rai1F8x6CQmtxQy5dk91JfhWGDbmxfGW3ud7djKPc9peC8VhAWXcrFxwVaWrSyy2obQTQfEctgzuXuIlHJ6p9aH7HqGlunVujtkgU9L29PfzmN7/5i8H4VP7WwYdr4KhqVavgsf7tUJ0cQSFPud8vVLLV6KGA6hcmLl26hF/96lfm3XfftZ///Oc/W3/r4A+B8+1vf3vJOY9Sopoh86XfTlsvorvpgGbY169fx69//evHDsZf5e+nfNiCs66Q3UM7j7rn1pX+bjbLg6H1K1/5Cr7+9a/j0wDjr/qXdj54RPqg9RMNpQRF/8CMC4Yq0C996UuiQD+Ozvib+ptMHzjg0F3cXIrRx/2jVa4c/7ii628SlHVwlJB5cL+9/lWeJwXGEwVlnXO+853v2Pfff18En7rJ4witf9PHO++8I0z6u9/97jPxFwH/H/vkoS0tqVn3AAAAAElFTkSuQmCC\",\n    \"redstone_ore\": \"data:image/png;base64,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\",\n    \"gold_ore\": \"data:image/png;base64,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\",";
    private static final String TEXTURES_JS_PART2 = "\n    \"lapis_ore\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEMAAABLCAYAAAArmToeAAAcxUlEQVR4nNV8yY8j55XnL1YG9zXXyqzKytpkWZu75Zlp+DKXuRqwbAGCPQYMH30xYAi+WD7ZRwE+Gv5TDBjdh/bF6Bm7e6RWlUq1ZVZWVmaSyZ0Mxj74fcFHBlNlyy1Vq9wPIMgMxvK939vf+5jAC6Zut5v8/ve/T/j+otdivqgHd7vdpNFoaL/61a/g+z5++9vfrhx/EWv60h/anTP785//PCEIpCRJ4Hke4jhGLpfD+++/r70IULQXCUIQBLAsa3EOQZnNZur9RYCifdkgaJqmNKDb7SKKIhimhTi/h6vrCQw9/W48HmM6nX7poGhfJgi2bSvm+Jka8PDEwx+6b2IcVdDIz/DfLx9gvzKBhuSFgPLcb9rr9ZJ6va69++67CgTDMFAoFNSLIJCoEa7rqvfOrIoPervoGQEM00XVjvFKJcJ+2V0BJQxDdS8C+otf/EKT5zzPtT+3m3XnEnv//fcTOkNKlEyQGYKQz+dRLpeh67o6n8yJ1Em9MIfb0wYOBzsIgjwajoevrx/jenOkQBEny3tRSwjKu++++1xB0Z6nOYRhCNNyYFk2TCNlgAzzRUdJIPhOCY9GIxVS+Vm+I3W8Cv5weg3dYYAkmKBRiPCN/Qn2WuEzny+gnJ+fJ81m8wvxoz0vnxAnGu6dVvHhUVPd9mv7U9zaHiIKUnMghbEBU08/8xijCTWHRFAirYg/PrmB+50NJJqPvNXGzcYTXKt34di60izHcVbWQVDpjAnmr3/96y+kKdrzCJH3OmXcPq3A9UxEgYUwySEybTh2hFc3T1G3Pfzp0R56kwK+cukpXtk5Qs4MFqDM/AhaQslrOB6v425nHzv1Pl7eeAIdPjw/QBKnIJqmqUARIAgoX9SQRqOhvvu85qN9ERDCMFQL6c9yuNtp4XiwBt8vIYYBmDE2q1280jpEyfJw5+Qq7nUuIdIjWJaPr2y0caU1xN3BLh4O17FbOMZL5U9QNCcLTTFMG/cGFm6fW8gbIV6qudhrmCiVSsoE6ZP4zr8lXyG44lvoaP8j0eczTzqf2+KPfvSjhA8uFotqoSSqOMEQM+hNy/jwZA9BkOBm8y4ahb6SGKVJ8iIbdzo7uN/bRmIXaPDpQxIg8kLEfoC96gleWXuIkj1VX524Nu70CzifriHwN7FVjvAP19rYLJ4rzeCasuYjjpYv8Ul/bUj+s1925xe/9957yWAwUKGQXpwhkvZJ5CkNHqOGiEMUkPiZIDSbTXUOpch7qMXGDu6OruH+6Ap810Y805HAg2G4uNF8jJdbh8gZ3soyj8ctfHB2FaVciK9dOkLDGSpBkLgOWYtoyOfJU7S/1hzCeZw3TQuH/Tw+fFrCWhV4cy9E0ZytgCHEhVFqBCULhpAXOviofRP3zveQaEPYVgc36m3cbJ4jb6fXi/ZlHa0wnAVDohG/J+P8u9frYTgcqu9FO/8SKNpnZYyWZS3CIxcUJzoe9Cr45LyK6chEMNCw2xjj1etdRLDw70fbKrJ8decYzdJ4Ffm5NnHBYl5KUyILH5838XBQw5XaFK9tDVCyU0a5lskk9SOSwRJgXicONAuSFzj417ubOHxawI1L97G7/hSFQl7lOXwehfrnNGXxx09/+tOEzIo/ILK0Qz6AqTMfzBsJRbGOu4dVfPSgBtc3oGkRNNuGkSugXgH+260R9jd6GI+XGiMLjmHhztkWHpy3cK1+gL3asUqsoOmwLXMhRZIIousWcH+whbV6Hm9e9VHNp36KviELyvmggj/d3cNxtwa7OkNrY4DXtnu4Uk/TfAKR1XT6wF/+8pcKB+1nP/tZ0m63FVICgkhPiA/ixZQMPbdkmAQvinTcPSrh3x9WYVvA392a4uVrEfJOqqoiXS7Y9SLc627gTmcXblCGphm43jrD17YfwtbGC8nxeRQEpdmZOPi3JxUcD+ggE+iWAbtawK1NH2+0BqhYwTNB6bpF3D5fQ3taxLXmCK9v9eCYyxxnafYm+v2+4t+kHZ+dnSkAarWaWgRvnAWFLyLK7whIb1zCH+5cRjHXx82dU+yue+gNgVIRuLzpIwwijMNgxanx2pMhcDRsYhboMDBBzfGwX3+KUs7Hk3EDt8/LaBkn2LLPkLguggi43ynjbERgqbUejGIBWs7EwVCD5Yd4uTZQAuJz+BJQGpjgGzsTxDBRcMyFYMgHweCLydrR0ZE6/9atW8tO13ReSzBaMHkRUGjn4vQOz6a437Xw8HENwaSIJCnh9uEWgiBCEofIWSEcy8VX9wcKAGqEOD/eq+4kuFY5w2hYQKTpGLoW/vHuJeRydXiGBRg62nDwVCvjRmOALWOG1zbOcKt1jvu9Ih7188iFPl6vjnClOoE7GWI6jZVjphY9C5RUq1MnS174og/65JNPlIMlSGIFCzC0eUUpNpoFhcxMZyHudkvozAzkmR5XhpgNq/AnZUA3YFSAm5fb2G91EQSxUkOqoHj6SqWC9qiCe+1N+L4JzQig2S6VFjMVRWPoGrVxAs+I8cFpHXc6eVyv97Bb7eHl1hDX62PUqiVUSqyA8ygXnYUQ+c7IQSDq9bp6JxD0d9Rm8kfm7927pzQiS2I2CzBMM1Wl1A9EC1AIBoHhDV9f78IqmrjTdvCoEyJfP4dTGSBAHhFs3Os3YBkxbjXbSpt8P8THhw14cRP/45UhLq8H+N/rR/jkqYN/eWijO9GhaxFMLUQYlxFHFrykDi0XI0oKcIMc7nQLaNSKWM+fQ3NdTMdDeO5EOT6uS96ZC5FJMk+t4HEeI5P0iXzRNwiR12wFvaIZ2Qgi7TeexHe+ePMbN26gXM5ju8VsU8OfDpIUFG2I3aqHa/UJcgZDl4ZHTzfwwcNdDNwc4wQ+OKjgzZd7+LtrY9zccrG/PsGdoxgfHZsYugZaFQ83tw0c9TycDWMUjCmu1EO8dtlAscBMtarMQPIVmgCZ5jEKiv6O6k6GGXqpCeTnwYMHChQhHud5YgnkVc7VfvKTnyS8IAgCdRLBkNAmapb1vHzozs6OkgbppOchnI1hIM1NeN7tR7v4050dRLEGmFNo+SkshwxpMK0YX7k8wEut87l319BzLeyu52DMJXU2TKD5PYSBhzDW8Xiwge2Whb31ZXFHICRnICP8m0CIIKkl0lqUhE21GTNJW5boQBdgTKfTVBPMS1irGihay2xSKsNshkdNoQTkxuJkBfGxm8O/PSjikxPmJIBhabDzNiLLRgJNtfn+59VjlJwUgGx6T+aCSMP/ua/hg8MiPJXHAJc2Jvj6foCdWrouYZxr4+dOp4ODgwOlOeQlm7XSmRMwPiPRHXihjnIuWAFjxYEmSYL2xMHHww1cqnWxXx2iYMSL3F9loPMH0CPzRRWllkhZLVTKe/jGVz38/U0bt5/mcf80QhR7qBoxrm/42K2MgDiB62oLR8sFT2cBHvZK+H+Pq/NkDihUprBzM4yiGP90D3h1PcYr27q6jlGE6/jjH/+o/ALXIWYgEWQh1NBGZ1LBFBZqjr8CBmkBRq1WU8id9DSwtXA6tdCNHDRNHXslX2lK1ukIUQqURrVaxd7e3iJ5I/FztepgowW8ecPAk/YMFZNOLLVTwzAXTR72NI5GZXx8VoAXMgROUCjqyBdd6Iw8GtDKabhRjVC2IzBDJwiHh4esrJUPyVI2aST1x2U8aZeh2xEMJwWBgqUCfCq0kijhl80eKsMQJ4GDMAFOpg6OBk1s5oe4XhugmEs14yJxMUze6HPo1CgxgiuzkZLj4NaugzBsqRCYXexwGuOfD0qY+gQ6hg4NhWoM3aRBaagZPm41EtTmJkXfwGQpGx0ILjUlqwkkSbC8IAdaMqNdqzhBxZ4hilJ/Q1oJrULM37cKXWxCQyd08DhyECTA06GNp508rjY93FhPtUSdPy/oxHzEeRFY5hbiUyQLzdY//KxykIKO/3VrhgfdPG4fAH4QY9IGru6E2LTbyCUzBCMNx90Ap6enKl/gM7PEe8oaJMuUv0m2GWG72Ue1nNYosna+xMd8CgyDvUg2a5IEa6aLVvUJTuwaDgclzBKgN04wdNKymNInZbM4ITpkSo7nMHkjUUvk3GwkIGPNWhlrDR1vXAFuP47RLExRybOqLeP4eKRMkWE1W8RdJOV453VUVksISrW4Gl6l6STOl2RmO1UkLpQMUMKqzU9NyfeQBMDdCZlKL5ZUW+qXrBSoARJ9/lxGK2FY9UDn4ZuaRD/zxr6OJCniyZMnuHPnziJjlHzgIvBcD5njcUpZjomGPAuEi8dUoSYl7Wg0UguViZcwLIUaKU4cQKvANM8XvQi+kwnVIZ+rPV8SIoXRLCitVks5XHmOSFLCJDWAINAHCUl+kAVC1sjrJe8R35GNfM8CQdqDUo2r6+RDkiQL25EsVBZKhnP6FLaRpq1c0Cw2cTTSsFNOj3GhzPT4LtMzCcm0ccn0CAgjAJ3sxsaGylfErzyrdngWCMwREKVrFfIjHaejImq5BM688/4sEEgEXICQ+5JHk4xTSrN5Ti9ok3gT0YCSNcTfb32IcZDmE7SyM9dE281jc1zD9fXh4lqRjsR5CZ8iPelP8pnMC3hcQqSo9TNBiAycDAz0XR3Xa2koDRMNfc9Ct1dFHBuo2ulxef5FEMRHiHDEtHhcQSbjP2detmczN7FrvnTEqNgD+L4GLTFh6ya8CDg4L+K4n8c3rvSXA6N5N0k5qZCLWjpPKQbFpzBCMNySeM5FRrzYwOmkiP7MRuylrURh5FHfUhkufaCp08elz5V8hy3Icy+HOJihpKdClhEln8FzF8In85Kza3MHpSTnOSjYPnQtDYVdv4GRb2IzdwYDDEMBXmuGOJtGOAxC1RsV8AQEAeX24VVYxhQ39wYo56OFX5GkRygbrkUTzn0dA5/ZKZnjuQaQ5GCaKXi83NCBRmGAmjOFBt4zLQHaExNdAmEYaJhpb0aaw/KMbBmgHCgBedCuoVYC1kqpvZ32KzgdVLHb6uBSfYAwMXA03cLTyRo2rBNslzswtAibBRfr+Y9xNk3Dp9ifOFM+mIvrDOoYP3awUZ9gvzGGbaTniNatqHNs4HhQxSAwYdpjBYFlRKhbE5y488JkTk0nQNmKFrmDmOFBx8CEHbUcoHGmZehK+7NJmQhDzHnhWVxPx9F5DrZTwOXmGFQ4LzRwv93C42EZ5UL6MFaRB/119NwSXtu4n0pUi7FZ7CjzoWZk+yJ831k7x8NgDTS+s3EOzYKHtWK0UkbLO2134JvoBQ50I4SlJahZU5SNgWpCn6Cm5rUSLSrWMoHicyWqLRQuDpHMXOh2Gs5FW7m2LDBKcPKHpqdXz0I2b5rYLvbVePBsUoEfGui6FjSV9PEGmrLFrO2Ko+WD2Gmitkmusl7vY602QHtawjE7Y3MS08zu25AIQU1Yc0ao2hwTzBlGgrViFzVniIh2kKGLuUN6Tw1JFELT0nOl2SxaK2Ytr8UddCOCaYcI4tRx5Uwf27UTXKpbeDJsouO30iUlOpDkEcf0ExoMbeloWThlhzXSi1yAUhxhrThGovGc1D9cTKL4ue7EaOlPP6X67LPWnXTSRh/VnVXQzA+VnxCSCKTPxP8AlVwIGwyny/Nk48sKoCt/aQkIohYZSOZmnDMC7NdPsBN38WS2hbNJSwnK5bDmdAs7lRF27eXkjdK9d2ZirxXB1JNngqIlgTIpaTVmGWGY5TmiIWIOYkocag+CKjrjomoeccxIjuOE5rqsVglC1fHQyLsqymQ1SHIroUXiJwcuVZgnlNAJC+zRIgojZX9yoa37uFo4wHbuBEf6Ns4mNZXonIxL2K0v02Xe+JMTE4/aJq7t6NitzGBq8TNByUYS0RK5j2iYpNfq3pqJg9ElRImOKE63MPQ9BwPPwV59AttYdrTWCyNomtxfAzQThfxqf2PkAVM/Rj2X1kkLMByTGnCOzeIEj/vrC6lwUcwSmQ/Q3jgQvtZ8iJ2aheNRCeNguXmECRSZJXHm8WBQwONJAa/XT1Fx0mF1FpRsBrmioHOblxpGQjEjGoFI2TOBxMC5y0Ru6YAlT0rB1DAJcmqg1CrHKGpppBxMDbTHQJCEKNIrzFswnxoVFOwZbq0fKrWLwuWokSpMMET6NJ+rtR4iLjBaNlnV1gA6V3W7BEGsYzz1kXjeSu2TBeSihmTVd7WeyPQq4qU5VGwPiAOEC20jCCZGvo1Z6CBOeG4a3dpDHScDE4YZwbTS64VWRgXGPDvkAml/OvuF83CXBU0BE9KhRSrXoIAlVC0yxwSIJz3ouTyQT9NfqrzMMRjzRZIXp/cC0DLkauhO8zifFhcrTn3CEM1Cb7E1iuTGefT8snLw6W4g+hKWAy5mGhNMZ3G9YcaLKKow4OKyGWh+nphIg5jfsY7I2ho/e3EJH55s40r1KZos8efM8j4b5Tza4wKQxIhnY5Q287B5zbz24f1YJV90ZHyeTPHSkaaG7qSknGXIiMHj1ARrhFqhD0sXIUlpr2MwrcDn3jEQUEtFGk2Zh1SwOufbcxCSlf0kOhcg+yyFZCxAiubqmE2MpHaZBjkcDLcVU6nzS4uyq/U+3tg+w1qB6TwfnILMgpCmkvUHsn9Dapmsybi+jZN+BWFEfwPUchNcKTzGmt1eADHyS3jUv6SGWAtS0cFBEFL7UrBtM+3TWHY2gHK9aYdd+ZmLPcPjvoFKURefgrNhGefjEvbWzlHKpZtN0m6Sz1ult6STM3P4eLqJDbuDTQSq3L9SDbFVNqCzD4JUC7gg+gvmJAKI+CExMwIrKboyh/wYjeIApr4UmOQnJ93WIgEceTkEPpCoa1OmCzlgq6Yhby1zmTTK0Ay5YyheZqCMFHxpc1D6Uw23T0xU9CIuVdITR24Og1kT22vDRbmbqC4YHSDQGRdQL84wi2wcuNsYeOfYKHqoOQFsPUIwm2AYzBZTfD6YGpHd7SN9B9EatoL9WMPV1tEKCFntXco3xmGviiBkmkaNSVSFres+6oUQeXFjyg+lGWm2DyqbbBV82V6gNk9du0MLZycN5CjUuYPiAtiUodT8wTymx8BHT1socKcNEdc1zEIdB4M8joYtbJcHaOSn6hpqA1VSqet8DkNw+b4YRoF+IofTUV6BsFNe7U9I3iHMafAVWwQiq/5ZP5FtECfK7NlWBEIGIUOHUZpHzSzaURRhpzTAjeYABTuVhuclSrKBly5aQGlVdby6cYiqk+7Km/oWEj9kywlRnBqZG1q4112DZtcXzlJGgwQlW5eQJp6OO0d5POk6KqETRkgSkrNrTf3cMrFKYpYKy3PydgxbTxs6ix4tfZiWIIkSRuOFdqhcRi7M5XIL1as7M7xxtYOXr/ZRys/T4nnjNtv8Kdsu9munSCL2GOYVqPLMZXh+Hbo2D226rkyRvVKpByQxkgkYFzxxE/gi4SQdZmXHhNlSX44VbQ+Xqx2Y4B6R9DvOdi43fOzWfTUnyQKY3mMOsKWhWVluylm4Vms+16Aqix23ajP16gxyCKKUiUXXKzNd4yLojBg1los1YGsDGGaqDVRCAWXphMOFVEQDdD2hawMiJjpLrZUUQEjMZltLw7oCwYmw1fBQdqg1rGnS5k8cZ2coBhhQWsUEjdJq8Pj0EEmbhyLbXjDeqno47Vn44EEN+9tjFJ1UWqqw0nXUSwF6k2WbzjJHiOJ0psKI47pjUECxXlENpOxOwtWELoFG/5RwjgY41vKXSgJEdgOMED/vrbsKDCF2yU5HDvKGh8p85yCfW80DrVK64yCrMSuFmj/fxLoYqMxrktPzGHHIjaXAWddGGBbw6n53kaTlLOAfXuqiM8zhXltHb8LhYAhTH+HVHYbqZa/ioyd8nIWblzysVeIVUFKiQ2RJ4KFe7cM2lpnp1M9hOCvg2pb/zHTdsdLCbRYYOO1b6M9Y2CVwCmmtJE2n7LXkWRJOdS9BPJmrbrZiJE1mBXz0sIU8y/RME+biXgduNmlVGGZNPDiJMZrpqFAKZQ1hWMRslkaBoavhg2OgOoxxswWU5/PTxQiwMlyMJBZSDi0cdWuwTArKf+b40PUMnJznMfLpIdkYTcNnttchJCWHTPSEFBgXh0XGfD9D2ktIB7ZTjxFCgxfF8CJT7dBRqbpr4INHNbx0ZYJKIUCrFKKw7WLgmmllCfZB05DM7E+b74Ieewm64xDW/NdGJHXPeSInvQ7lvyRgJCkTWRBEOPeeFOCzZ5qjH2JfJlAaqolXzQCxTOhWo5kpKhLO65DsVkfltLQ+7BIQTAsqRjMF/9fTTWyVxrhcSafgx+0cnnZyuLIzxvXNmfJ71XyIwA8RR5kf1/C5elogiUCyi8tWyDIVI/mhjjigSq8CcVE76GnYDYujACZ3BelpVith+eJzLnbYzPfeew9ra2vaW2+9lchEbbVbncDMuTBzM4ReHlHIaRswUJoiSyCXCU56lrLXZl1X256LdjrHFZCRMCIRFO6JCFXkyNLFvR9TNqlPSxi7Jttv6lLu4jnrOdhs9Fev5SoSKk+k7m+ZwEZNQ73E/GbpgC+2C9hZe+utt/DOO+8s94632+0kC4rQYGbgYFBEyP1Zc+a53dkxNbyydgbXy+H/3rmmpGCVeJ2GxE43l3x9+xSOvVTFD586GLgWcnn+fMvHbilG00n3gMsQicQmzskoh+FYQ5huG4eTC1Ev+zjrVZQwbl3uqJGCpVp6CR4ebyozsZwx1qoe1uqa+mmokMyHBAya7dtvv61A2NjYUCcuPOXa2po68Jvf/GZFU0qWj+tVF6OwjDM3jyBk3u/DpKSylACBN4JhWNDttPyOVAK2NL25cs+THhMJVvsYS43QMHJTRvhrJuY65UKgqtdTdhg1DWfTMoa+jf1qV1XGlhmjVRuhXnFTn6FY01ZGiqIJBOG73/2uAuHHP/7xZ//epD3XlG9+85sJJceblMpVHPU4TkxgaSFeanHUp6M9aOHgaQ0zdFIGCjES3cIb211YmcbL3fMyRp4J24lhWAnWjBEaubSHwaGzhNrhzERnYqLhzJSpCc18CwenTRUjjFIK5LUawWCIZX9zuX5J5MThXgThc/0S6ezsLFlfX9fefvvtZJEAxSztI+SRFlFq506i4fjcxEHbUj/JIr1+aaTS4UWjuFvCyDNSSToJ1u0Ryrq72CwnnWt20RbteaVHBk57JQwn+UW5bpbYKwlxtTpUmvCs7YwkOs9vf/vbfxGEvxoMoU6nk7RaLe2HP/xhIs0Qec86Pi625+bxqJ3g1tpQgUEGCcbddg4911A1Bwulq+seKtZY+QuaZDbpIy16pYGNO4/SCb6KRrYHQ/2aIMFedaoi08VtB1nH+FkgLJ6H/yB15qD84Ac/SLIbzC4uhA1ltfdyljIpTrQ9NvD43IQ7A65vhtioRmq7kzR7pJcqu/BYL01nBj4+zMPgIHwOAsnUgSt1b8VRfh4QPjcYF0F55513lKZkSfZhCIkGCdl2Du0hQy1/RBOuRBPJcehHZAPu2I1w0LNWQGiVgUaRHfzUOX4REJ7bL57bc0ebBUVSetEIAUNMKtsuoCZwkwp3/WS3NKgG7XyAzX2hT0Z5tfVgbQ6CKAN9xbe+9a0vBMJzA+MvgSI/vs3WPrIZLbs9gNuWCEgWDJm4qWFxrGM001C2A9Sq6eCa1//ud7/TxMHjb/G/JLQzoFD1s9uFLm46I0Pql029ngLjWVsUpKBSsxxdV/vAnjcI/+n/P6P9ZzLaLIkp0WdkfwZxceAs2kRT+P73v4/nDcKX9p9V2s8ARe3sz/zOI+tAL07d6Ri/853v4Hvf+94X9gl/M/9zp50BRVReiGAwvF4E4bMyxv/y/42p/QxHSyAkZ3kRIAi9kP+HdRGUk5MTFUpfFAh/M9Rut5VdnJ6evvD/4Pb/AYo42wMNRK7ZAAAAAElFTkSuQmCC\",\n    \"diamond_ore\": \"data:image/png;base64,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\",\n    \"coal_refined\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEUAAABLCAYAAAAmh0pZAAADAklEQVR4nO2czU7yUBCGD21REHZG451AJCy9Hi/ApAsSr8qFCxPkUlgrAfmtmS7bZ5KeFPKZL++TnM3J4Vhe2nk7M60hnIE0TYu2I8/zIvwRkn99AH8RiQJIFECiABIF6IQI8jwvXl9fa/P39/e4PkkSnKP5r6+vclR5eXkJs9ks6jjbojMFkCiARAEkCoAB7O3trfj4+KjNf35+hsViUZu/u7ujbcL19XVtbrfblaPKdrstR5XRaBTG43Ft/pLBtxPjMjc3N+Wocnt7i5sPh8Pa3Pf3N7qMx2q1KkeV4/F4MVF0+QASBZAogEQBshBBkiQhy+of6XQ45h0OB9yj1+vhWlp/dXWFAfv5+RmLUudwpWhR0jRtvD5GlJ+fH1cUG1XIHc+FLh9AogASBZAobQPt6XSy2+vG7hODpQ+DwaBxTvTw8ID7LJfLom2hSmcKIFEAiQJIFECiAB1rblcnh8Mh5hvevN2iE+RURVGULlbF0gdKIdbrdTmqUA5mUFVvs9mUo6kr6UwBJAogUQCJAmC0KpxgaIGTah7ebT4FPS9V8ALtfr+PSi3o+Oi7XFyUBBrmBuUs3h7mJp4oMT+ErW8rii4fQKIAEgWQKE1v8weDARZ8rGFOTXMP6gF7QdyCNQVPr/XhBXfPfcjBrHH/+PjYLvfJsgxzDvqDnhPEYnt7ORQRUwX0ciJdPoBEASQKIFHatjgOjhOcA88hPGICqrfWm9eZAkgUQKIAEgWQKE3d53g8ulUzylu8fCjGTTwsVYgpHFEa4jmbt4fOFECiABIFkChAZv3UKvP5HN/W8CruXm3jHPUUC4Z0O+71kmmtV9iaTCZhOp3W96YGc57nxfv7e21xv98P3W4XD5wgB4t9FMzW02e853npB7I5ch8TRA32hiimABIFkCgAhvDpdFo+5RPjSoQXIL2eMbmVF5i9FIICrbUxzGmqkPMY+G2enp7cdwvJleitDA8ThN7KuGRVzwTRw8UtUUwBJAogUS5Fqn9U9f+jyweQKIBEASRKqPMLb+KawHEkylIAAAAASUVORK5CYII=\",\n    \"iron_refined\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAAA5CAYAAAB+pNYgAAACuklEQVR4nO2bP485QRjHx2UVEomNjT+hEIUOCcm+Al6BUrnR8GpUNLKlwlugVEgkFBTbCRFUQkNIcFnVze5eZp41637yez7JFDOZG+dzO19zzy4f+WB0XX+w5uRyOaKqqk/E60nkg+l2u8w51WpV2Ot9CVvpPwBlAUBZAIQE3zuC2gnDMJhzFEUhkUiEGtM0zfexAd/lCGonarUac85kMiH9fp+IALchAJQFAGX9VWaVy+WHiOzJZrNms4WwYRjg9ePxOCkWi9Zh2zqDwYAZ+nhlAUBZAFDWq5kl6pAYjUafjSdXfvL1Je5vGAwGbes7ZJj5D/eDVa2QvDwkZn8Jap7gdhPmv8kyG0tWp9NhVitwGwJAWQBQFgDJKcyn0ynVTyaTJJFIMBczM+on1qx4B6PRiDlnt9vZxsLhsO3Dqt1uU258TqfuSqVC9VVVdV3HFhXUvDSbTSHrbLdbstlsqDHchgBQFgCUBcDxUNpoNKh8Go/Hj1arRWVPOp1+Nq9Cmieoncjn80J+h/v9jpn1CrgNAaAs0ZVSWZYd82mxWFB965z1ev1sUA6HA4nFYsQr9vs9c875fHYnK5PJ+KyHS1MUjyw3QW2K+hdl4TYEgLIAoKx33Arz+/0kEAhQY/P5nOqfTidX2cNbreDJHs9l8VQKJEmyyZrNZrY3/ddBLRLchgBQFgCU9Wpm9Xo9rofEFEUhXmWR2zwyP1RYFU8eNE0j9Xqdqr7glQUAZQFAWQBQFgDH21vW22OpVOrZWNxuN6p/vV7J5XIhIlitVmS5XAoJarfglQUAZQFAWa8eSq3PJjnlhSzLJBQKESjH4/HZoJhV2FKpBP65QqFAPJVl/bqG+fDIcDi0zXMry01Qm6JEBbVbcBsCQFkAUBYA1xmg6/rD+qAuT3CLPCS+G7yyAKAsACgLAMoi/HwDuL7yVDtENrwAAAAASUVORK5CYII=\",\n    \"redstone\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABFCAYAAAACRBuaAAACZUlEQVR4nO2cv2vbQBiGX6UOcTvYQ8kWMjRdMjSLtwzy5AT6L2RNAx4ydfbkOVOGQvdC/4XWkzxk61JjAiFeQreQQAINLQ1xUHuTfJ/oK05WDO8Dt3zoh/Wgu0/67uQIFXLc600/9vvUPiMgQkUsVXXiRUSyCCSLQLIIJIughjllPXiYJAk2yGMdGMc67PdLz5JzScNvAO8FpqJekccaVPhIoW5IIFkEkkUgWVVlw2MjUz0z3v+uXcvyG8Av4xwN8tytOMZ2pxNk8I/mkfW+G9t/BfDFE79xzcdPI/7DiB/0esEeK9QNCSSLQLIIJItAsgiikKXgDsrnlNz+1rUQWVJ3FoFkEUgWgWQRSBZBxGa9jQLVzXlkwysj/g7Avif+wTWm6qo7i0CyCCSLQLIIJIugZpVjoyRBlygF52FVPesAVjzx1y7rMtnwRc72nzzxswIl6sgqBaeiukQpOI8LI950LcsugB1jn7coH6tErW5IIFkEkkUgWSEmWSduMM8yzsluTTJeJ89dhHsAfzzx5QIzzLmy2AnQJhm3OHctBKmoO+NRg5WlbkggWQSSRSBZBJJFYCaES7dOKssqgHVjnyMj/h7V8dy1EOjOIpAsAskikCwCySpzkrWRU4612CxQWbWqqy/JY+25lkWTrCWjbkggWQSSRSBZIbLhyWAw/TYczsRHSYKxJ54H+7VqXjXWes/zLbJN2fr3mcwMD3GMabvt3cdamBt0tbLFGqqbGLXQauWS0ZhFIFkEklXml6ytOP47ODJ8JhNCEdjflF7HQv2vQ0j0vw5PDI1ZBJJFIFkEkoX/5xHtDYnU75i8JQAAAABJRU5ErkJggg==\",\n    \"gold_refined\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFEAAABQCAYAAABh05mTAAADvElEQVR4nO2cT0sbQRiH38RWVntxL1LwUtNelJy8t0hBvSoEkoOVnvoFipeWgCDtRfoFvDYXg5BAb4ZCTbbpoVbooQpVo8QioZA/B02jsdmy1VJndmU3k1ej8ntgDzPMZvXJzPvOzs6G4vG4SaAl/K2dDiCRCfREBiCRAUhkABIZgEQGIJEBSGQAEhmARAZu0Q0kFou6rgdMTs76uK53IyUuLs5e6vUwnBmARAYg8abHxPFxUlowTiTuuLaZmDiwfXYySUrJBj2RAUhkABIZgMTrkFhisaipOvm1J4gX5PO9FIK/ac4pJp8Z12QTCkU93dmgJzIAiQxA4mXGxNXVlLm2lm76An5/hiKRTqn24enhxmep3EGm+VGKgVlSY9hWE4mkhHKjkbGtCA0OPqKhoRGfkkRLoEqCiEQ6KRy+LdU+tiUIJ8Jhp6ShKs1dYjj8QSgvLGQpHhfrrGQjg+HMACQyAIkMnBsT5YB6eLhMY2Nim66uYdI0e2w5SzDY4fBd3XNIEE7wxL98Pkf5/JaHlnWhVC7/pr4+sUUut0zz86KbcyXKScQSKEvU9WHS9Zmml49OBHIlCHcsgZnMktK5ssSNjTQtLYmzFAxnBiCRAUhkwPNkW9dnKBAQ41+5TGYuJy7h9/fPefg0tXhoGCml2BYMWpN+YiGRsOKiWIeeyAAkMgCJ7V7Z1rT7pOujQl2lkrK10bSA4uRXpFbb+hvfmqW311s7c6XbvdFe3TYpb1FigDRtRKjb3p4WypZku0S1ya8lUEWiV8yVLvc2e2STiOHMACQyAIkMNBETdx1WXnZtrXRdfBSwv79DhYKYbPz+K5AgPPCrbh3ivyyXm5bo5U6jp0d8FFAo7ND6+neh7u7d9icIL1jCigcNW50MhjMDkMgAJDLgOSaWvhq0efTFtd2DJ3RhWAlDJd6VqvbY9mqjovQ3TE1F6fUzcX8OeiIDkMgAJDIAiReZWOSd9KHQc3Naeow6OtBNIwNioN98qwnlUqdJ1HlkSxCNHzwT4qfZotJ5hqH2poBh2PcjoScyAIkMQOJlTratzY3y3rzDn1lKrX8S6uQY6YR1E29NgM+SLtZIdfLLFdsuXKK8O/Tfpqd36fdKEuvSHURyt0oqGNLdQzvAcGYAEhmARAZaemTqlGxS394I5UqjTmUx/FFH8Zj8pdqVSxBtkeiUbMald5Sr1ZND5Pj0+I+8vHSdwHBmABIZgMSr+KpuUvF3FK4z6IkMQCIDkMgAJDIAiQxAIgOQyAAkMgCJDEAitc4f9hYyCP2ANXUAAAAASUVORK5CYII=\",\n    \"lapis\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAYAAACOEfKtAAAEBElEQVR4nO2cz0sUYRjHHzf3J5vmtoumRZIFlt5cIzDoGEGH6NKfUBB4DbpIl6BLh05F4D2JKAyiIkhQOtSKhxTDTTZa13JdXXd3fuzO6sYsdMh5ntqZZ3WVng94eZzZWT/M+H3f550ZGBsbq4DgGJfzXQURWAeaYY8S6Ltt61+LP9xe/cHw6F60/iPxEa3fun4BRoYvNtVyXLmEmYhAJiKQiQhkIgL3ewoHiLS9cu0Gun1mbQMya1lLvWDkoVDKoftcvTyE1t9/CKP10fE4+r2wdJYzkIkIZCICmYhAJiJwP6Twu6kvlclYAv3diykFrauqjtaVolJNXIygpwWtJ5IZtJ5ejhPfGCDSecpSm57Pw50Hryu7LnAyloB7jybAznAlvbqO1hVdQYcrpryg+yC6T+L7Kn6M1AIpL3LkpKU+sxCHtxPTf9TkEmYiApmIQCYikEnzbqTt4nIZBs+eQ/dJLi2jdVXV0LrL5YJIS8RarxwA2AJbaRs81IXWPT48jHZc4CSRtqY8SuCzl1O2jhEKtUG41doE0PUiaHrRVtp2dA+idY8vUPP3kUuYiQhkIgKZiEAmIpDJrsyF82oZUmm8OUBBteHNz8orZbTVT6Uwlbahw3hLX9NUWMtY58+aqlpqcgYyEYFMRCATEchEBO6HFFZVneww9/ScQOtUapvNh2QyZakXsikoZJfQfc4MXELrWNL+67O2I2cgExHIRAQyEYFMRGAjUnj74vJv5r+VoLc/CtsJBENA0RHB2+ebxC3mJT1fTUnL9kUAt6uLnNvWg6GB43A+2s0XSC2S9/ZHobcvig5jFGKNoz0ctDWMKek5dIhhynM3daL7YE0AJ5jy5P7AOiP/A5mIQCYikEmzk7QdHbemoInH14relrah5CBb2ACMzwsFtL6y9BOta1oRvfVsq+yDLWujuoo/gK/zplNxMunrIpBKW2py7vZ60bQ15aVzaXSflVU8ndcX7d16Zg5VqLT1+3GBtTYM/oZcwkxEIBMRyEQEMhGBTBzNhedir8i58LGj1rlwJNwGp8E69DB58zRm69hm0lKteIrEjL3tqSfWR4bvWraVM5CJCGQiApmIQCYisBEpTD2eNT/7CZ4/eWjrs6h5NQBep+a8xRxAEe9XgLqJvx9Gnb2LvhsGS1sKOQOZiEAmIpCJCGQiAhuRwl/n8OfblHwT+fwZBbXojS2em5QNAwzDQBfWyxV6bstN2zoLxP84b6v5AB++uE1BteGp59ucMDJ8s6ZX2TlBLmEmIpCJCGQiAncyRKj0uv8YX5CuaAAG8dS4XahjO6EeaetIIPUiVuqVdYa5Ro6vk++p5KwncgkzEYFMRCATEchEBDZiLky1wv9H5AwEHr8ADW51aTSxwDAAAAAASUVORK5CYII=\",\n    \"diamond_refined\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAE8AAABQCAYAAABYtCjIAAADa0lEQVR4nO2cP2hTQRzHfy+JgcYEogim4J9iXXQxdqjFjAEdHNROQqVaiJDBTSjYwcFBoahTBy2BIlgqFYOLS7W4GLVCa7Ook0VxSK3aakNs81Iir2Pud5Dkl3tN6PcDXX5c714/vOuXu3fv0eTkZJlAXXjq+zUAeUJ81AQET0SN/evIz8xbpvrGtBUAeQIgTwDkCYC8VknboCZVTSaiyTFx5wmAPAGQJwDymi0wpt+9KWfm59TBvPxwZ173iZdnQctLnb6AEgK7e0+z7QcHEsqYsWgXxXtOWlsqLzM/R8NjqaoTbl/fWbG8iMdP2eKq0s+lr+/Z9sMXrym1wYFETWNi2gqAPAGQJwDyBPhMpKplWTSUSCr1oRm1VisRr5/2evxKfWFjjaaLy0o91BagppSX0aSqI27oSlJJVi4NN+ulfNVjOuKO7QgpfY8XcuWX6+7Kw7QVAHkCIE8A5LXKZmhWEwz9gXZ22cYGTFkfPLdDh5Ta9dUv7JiHH91Vaqn0FLt56izbbiSvKteIO08A5AmAPAGQJwDy3EhbLoV8Xh+7wensDHMbnLpUvZP/xqbnC2atWisfHz9j60cvnFNqdluAftfQN+48AZAnAPIEQF6rnwxtFtqOdLKPKmfX/tDN+yNqYJKLZDVr0kakasPkdbQr9Q/pKZqeeKLUMW0FQJ4AyBMAeQKMBEbQ8m6eHakk/WOBbR8Kh8ltFt/OKrViyaZ121bqdm7JPXmdvoDFJevTRV7e5fBxcpscI0+HnfvJ1jFtBUCeAMgTAHkCjATGeCFX5h75HejoYNuPPBwjUwR7olW3LX7Pbf5UYi/xW6S48wRAngDIEwB5AiDPjbTlHjGWBkpl7pHkrdQDOtinPtrL3htl+97Ve4pMsZyeqnrMQvYzrTx/RexBn9EJHPRpJJi2AiBPAOQ12/KsWLJp9V+BmhluGbbxt/pXGozJW7e3hzxMWwGQJwDyBECeAFFgxKJd7KvlzsEY53xHJd7QTnIb3ZjOUqyS7sh+6u6KsX9nw+XFNR8zcE4UcQdj9vSfJ7fxaOV9UmqOOO5lFW3fskvb3kCeAMgTAHkCjCzPYpoUHpnLsO1Lv1bIzWWYA3d9ulR1VV5ck8K6b9lxyWcabme4VjBtBUCeAMgTAHkCXH0PI2/ww6pbAe48qp//YxsPeUVNv2kAAAAASUVORK5CYII=\",\n    \"netherite\": \"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' width='100%' height='100%' style='image-rendering:pixelated;'><rect width='16' height='16' fill='%232e2c30'/><rect x='1' y='1' width='14' height='14' fill='%233e3c40'/><rect x='2' y='2' width='12' height='12' fill='%232a282c'/><rect x='3' y='3' width='10' height='2' fill='%2348464a'/><rect x='3' y='6' width='10' height='2' fill='%231f1e20'/><rect x='3' y='9' width='10' height='2' fill='%2348464a'/><rect x='3' y='12' width='10' height='2' fill='%231f1e20'/></svg>\"\n};\n";
    private static final String TEXTURES_JS = TEXTURES_JS_PART1 + new String(TEXTURES_JS_PART2);
}
