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
            config.ores.add(new ModConfig.OreConfig("coal", "minecraft:coal", "Coal", "#707070", 2, 30.0));
            config.ores.add(new ModConfig.OreConfig("lapis", "minecraft:lapis_lazuli", "Lapis", "#1010a0", 3, 25.0));
            config.ores.add(new ModConfig.OreConfig("redstone", "minecraft:redstone", "Redstone", "#ff0000", 3, 25.0));
            config.ores.add(new ModConfig.OreConfig("iron", "minecraft:iron_ingot", "Iron", "#d8af93", 3, 14.0));
            config.ores.add(new ModConfig.OreConfig("diamond", "minecraft:diamond", "Diamond", "#55ffff", 5, 5.8));
            config.ores.add(new ModConfig.OreConfig("netherite", "minecraft:netherite_block", "Netherite Block", "#312c36", 100, 0.2));
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
        try {
            executor = Executors.newCachedThreadPool();
            server = HttpServer.create(new InetSocketAddress(activePort), 0);
            server.setExecutor(executor);

            server.createContext("/", new IndexHandler());
            server.createContext("/stream", new StreamHandler());
            server.createContext("/send", new SendHandler());
            server.createContext("/leave", new LeaveHandler());
            server.createContext("/history", new HistoryHandler());
            server.createContext("/server-info", new ServerInfoHandler());
            server.createContext("/server-icon.png", new IconHandler());
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

    private static void saveHistory() {
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

    private static void savePrivateHistory() {
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

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String from = "";
            String to = "";
            String message = "";
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("from".equals(key)) {
                        from = value.trim();
                    } else if ("to".equals(key)) {
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
            String query = exchange.getRequestURI().getQuery();
            String user = "";
            if (query != null && query.contains("user=")) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=");
                    if (pair.length == 2 && "user".equals(pair[0])) {
                        user = URLDecoder.decode(pair[1], StandardCharsets.UTF_8.name());
                        break;
                    }
                }
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
            if (nick.isEmpty()) {
                byte[] err = "{\"error\":\"no nick\"}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(400, err.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(err); }
                return;
            }
            File avatarsDir = new File("config/mcchatbridge_avatars");
            if (!avatarsDir.exists()) avatarsDir.mkdirs();
            // Remove old avatars for this nick
            final String nickFinal = nick;
            File[] oldFiles = avatarsDir.listFiles((dir, name) -> name.toLowerCase().startsWith(nickFinal.toLowerCase() + "."));
            if (oldFiles != null) {
                for (File f : oldFiles) f.delete();
            }
            File outFile = new File(avatarsDir, nick + ".png");
            try (InputStream is = exchange.getRequestBody();
                 OutputStream os = new FileOutputStream(outFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
            String json = "{\"status\":\"ok\",\"url\":\"/avatar/" + nick + "\"}";
            byte[] response = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
        }
    }

    private static class AvatarServeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            String path = exchange.getRequestURI().getPath();
            String nick = path.substring(path.lastIndexOf("/") + 1);
            File avatarsDir = new File("config/mcchatbridge_avatars");
            File file = new File(avatarsDir, nick + ".png");
            if (file.exists() && file.isFile()) {
                exchange.getResponseHeaders().set("Content-Type", "image/png");
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

    public static class ClickerState {
        String oreType;
        int currentHits;
        int requiredHits;
    }

    private static final java.util.Map<String, WebInventory> inventories = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.Map<String, ClickerState> clickerStates = new java.util.concurrent.ConcurrentHashMap<>();
    private static final File CLICKER_FILE = new File("config/mcchatbridge_clicker.txt");

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

    private static void saveClicker() {
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

    private static boolean transferItem(String nick, String ore, int amount, String toPlayer) {
        if (com.example.mcchatbridge.McChatBridge.server == null) return false;
        net.minecraft.server.level.ServerPlayer player = com.example.mcchatbridge.McChatBridge.server.getPlayerList().getPlayerByName(toPlayer);
        if (player == null) return false;

        String itemId = null;
        for (ModConfig.OreConfig o : config.ores) {
            if (o.id.equalsIgnoreCase(ore)) {
                itemId = o.itemId;
                break;
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
            player.getInventory().add(stack);
            if (!stack.isEmpty()) {
                player.drop(stack, false);
            }
            player.sendSystemMessage(net.minecraft.network.chat.Component.literal("§6[Clicker] §b" + nick + " §fsent you §e" + stack.getHoverName().getString() + " §f(" + amount + " pcs)!"));
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

            if (inv != null) {
                int count = inv.get(ore);

                if (count >= amount) {
                    // Attempt to give in-game
                    if (transferItem(nick, ore, amount, to)) {
                        // Decrement
                        inv.add(ore, -amount);
                        saveClicker();
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

            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            String body = bos.toString(StandardCharsets.UTF_8);

            String nick = "WebPlayer";
            String message = "";
            String[] pairs = body.split("&");
            for (String pair : pairs) {
                String[] parts = pair.split("=");
                if (parts.length == 2) {
                    String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name());
                    if ("nick".equals(key)) {
                        nick = value.trim();
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

    private static final String INDEX_HTML_PART1 = 
        "<!DOCTYPE html>\n" +
        "<html lang=\"ru\">\n" +
        "<head>\n" +
        "    <meta charset=\"UTF-8\">\n" +
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no\">\n" +
        "    <title>Minecraft Chat Bridge</title>\n" +
        "    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n" +
        "    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n" +
        "    <style>\n" +
        "        @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');\n" +
        "        :root {\n" +
        "            --mc-dark-bg: rgba(16, 0, 16, 0.92);\n" +
        "            --mc-purple-border: #2e0066;\n" +
        "            --mc-purple-shadow: #1f0033;\n" +
        "            --mc-gray-btn: #5c5c5c;\n" +
        "            --mc-btn-hover: #7a7a7a;\n" +
        "            --mc-btn-active: #3c3c3c;\n" +
        "            --mc-border-light: #aeaeae;\n" +
        "            --mc-border-dark: #2e2e2e;\n" +
        "        }\n" +
        "        * {\n" +
        "            box-sizing: border-box;\n" +
        "            margin: 0;\n" +
        "            padding: 0;\n" +
        "            font-family: 'Press Start 2P', monospace;\n" +
        "            image-rendering: pixelated;\n" +
        "        }\n" +
        "        html, body {\n" +
        "            height: 100%;\n" +
        "            height: 100dvh;\n" +
        "            margin: 0;\n" +
        "            padding: 0;\n" +
        "        }\n" +
        "        body {\n" +
        "            background-color: #141414;\n" +
        "            display: flex;\n" +
        "            justify-content: center;\n" +
        "            align-items: center;\n" +
        "            color: #ffffff;\n" +
        "            overflow: hidden;\n" +
        "        }\n" +
        "        \n" +
        "        .panorama-bg {\n" +
        "            position: fixed;\n" +
        "            top: -20px;\n" +
        "            left: -20px;\n" +
        "            width: calc(100vw + 40px);\n" +
        "            height: calc(100vh + 40px);\n" +
        "            background-image: url('/minecraft-panorama.jpg');\n" +
        "            background-size: auto 110%;\n" +
        "            background-position: 0 center;\n" +
        "            background-repeat: repeat-x;\n" +
        "            filter: blur(12px) brightness(0.55);\n" +
        "            z-index: -1;\n" +
        "            animation: panorama-scroll 180s linear infinite;\n" +
        "        }\n" +
        "        @keyframes panorama-scroll {\n" +
        "            from {\n" +
        "                background-position: 0 center;\n" +
        "            }\n" +
        "            to {\n" +
        "                background-position: -2048px center;\n" +
        "            }\n" +
        "        }\n" +
        "        \n" +
        "        .chat-container {\n" +
        "            width: 100%;\n" +
        "            max-width: 550px;\n" +
        "            height: calc(100% - 32px);\n" +
        "            max-height: 750px;\n" +
        "            background: var(--mc-dark-bg);\n" +
        "            border: 4px solid var(--mc-purple-border);\n" +
        "            box-shadow: 0 0 0 4px var(--mc-purple-shadow), 0 20px 40px rgba(0,0,0,0.8);\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            position: relative;\n" +
        "            overflow: hidden;\n" +
        "        }\n" +
        "        \n" +
        "        .tabs-bar {\n" +
        "            display: flex;\n" +
        "            background: rgba(0, 0, 0, 0.4);\n" +
        "            border-bottom: 4px solid #5c5c5c;\n" +
        "            padding: 8px 8px 0 8px;\n" +
        "            gap: 4px;\n" +
        "            overflow-x: auto;\n" +
        "            flex-shrink: 0;\n" +
        "            z-index: 12;\n" +
        "        }\n" +
        "        .tabs-bar::-webkit-scrollbar {\n" +
        "            height: 4px;\n" +
        "        }\n" +
        "        .tabs-bar::-webkit-scrollbar-thumb {\n" +
        "            background: #5c5c5c;\n" +
        "        }\n" +
        "        .tab {\n" +
        "            background: #3c3c3c;\n" +
        "            border-top: 3px solid var(--mc-border-light);\n" +
        "            border-left: 3px solid var(--mc-border-light);\n" +
        "            border-right: 3px solid var(--mc-border-dark);\n" +
        "            border-bottom: 3px solid #5c5c5c;\n" +
        "            padding: 6px 12px;\n" +
        "            font-size: 9px;\n" +
        "            color: #aaaaaa;\n" +
        "            cursor: pointer;\n" +
        "            position: relative;\n" +
        "            top: 3px;\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            gap: 6px;\n" +
        "        }\n" +
        "        .tab.active {\n" +
        "            background: var(--mc-dark-bg);\n" +
        "            border-bottom: 3px solid transparent;\n" +
        "            color: #ffff55;\n" +
        "            top: 0;\n" +
        "            padding-bottom: 9px;\n" +
        "            z-index: 2;\n" +
        "        }\n" +
        "        .tab.unread {\n" +
        "            color: #ff5555;\n" +
        "            border-top-color: #ff5555;\n" +
        "            border-left-color: #ff5555;\n" +
        "        }\n" +
        "        .tab-close {\n" +
        "            color: #ff5555;\n" +
        "            font-weight: bold;\n" +
        "            cursor: pointer;\n" +
        "            font-size: 11px;\n" +
        "        }\n" +
        "        .tab-close:hover {\n" +
        "            color: #ffaa00;\n" +
        "        }\n" +
        "        \n" +
        "        .header {\n" +
        "            flex-shrink: 0;\n" +
        "            padding: 16px 20px;\n" +
        "            border-bottom: 4px solid #5c5c5c;\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            justify-content: space-between;\n" +
        "            background: rgba(0,0,0,0.4);\n" +
        "            z-index: 11;\n" +
        "        }\n" +
        "        .server-title-container {\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            gap: 12px;\n" +
        "            min-width: 0;\n" +
        "        }\n" +
        "        .server-icon {\n" +
        "            width: 32px;\n" +
        "            height: 32px;\n" +
        "            border: 2px solid var(--mc-border-light);\n" +
        "            background-color: #000;\n" +
        "            object-fit: cover;\n" +
        "            cursor: pointer;\n" +
        "            transition: transform 0.1s ease;\n" +
        "        }\n" +
        "        .server-icon:hover {\n" +
        "            border-color: #ffff55;\n" +
        "            transform: scale(1.1);\n" +
        "        }\n" +
        "        .header h1 {\n" +
        "            font-size: 11px;\n" +
        "            font-weight: normal;\n" +
        "            text-shadow: 2px 2px 0px #000;\n" +
        "            color: #ffff55;\n" +
        "            line-height: 1.4;\n" +
        "            white-space: nowrap;\n" +
        "            overflow: hidden;\n" +
        "            text-overflow: ellipsis;\n" +
        "        }\n" +
        "        .header-actions {\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            gap: 8px;\n" +
        "            flex-shrink: 0;\n" +
        "        }\n" +
        "        .status {\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            font-size: 10px;\n" +
        "            color: #aaaaaa;\n" +
        "            background: #000000;\n" +
        "            border: 2px solid #5c5c5c;\n" +
        "            padding: 4px 8px;\n" +
        "            text-shadow: 2px 2px 0px #000;\n" +
        "        }\n" +
        "        .status-dot {\n" +
        "            width: 6px;\n" +
        "            height: 6px;\n" +
        "            background: #55ff55;\n" +
        "            margin-right: 6px;\n" +
        "            box-shadow: 0 0 4px #55ff55;\n" +
        "        }\n" +
        "        .status.connecting .status-dot {\n" +
        "            background: #ffaa00;\n" +
        "            box-shadow: 0 0 4px #ffaa00;\n" +
        "        }\n" +
        "        .setup-pane {\n" +
        "            flex-shrink: 0;\n" +
        "            padding: 12px 20px;\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            gap: 12px;\n" +
        "            border-bottom: 2px solid #5c5c5c;\n" +
        "            background: rgba(0,0,0,0.2);\n" +
        "            z-index: 5;\n" +
        "        }\n" +
        "        .my-avatar-wrapper {\n" +
        "            position: relative;\n" +
        "            cursor: pointer;\n" +
        "            flex-shrink: 0;\n" +
        "        }\n" +
        "        .my-avatar {\n" +
        "            width: 36px;\n" +
        "            height: 36px;\n" +
        "            border: 2px solid var(--mc-border-light);\n" +
        "            object-fit: cover;\n" +
        "            image-rendering: pixelated;\n" +
        "            background-color: #333;\n" +
        "            transition: border-color 0.15s;\n" +
        "        }\n" +
        "        .my-avatar-wrapper:hover .my-avatar {\n" +
        "            border-color: #ffff55;\n" +
        "        }\n" +
        "        .my-avatar-badge {\n" +
        "            position: absolute;\n" +
        "            bottom: -2px;\n" +
        "            right: -2px;\n" +
        "            background: #5555ff;\n" +
        "            color: #fff;\n" +
        "            font-size: 8px;\n" +
        "            width: 14px;\n" +
        "            height: 14px;\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            justify-content: center;\n" +
        "            border: 1px solid #000;\n" +
        "        }\n" +
        "        .input-field {\n" +
        "            background: #000000;\n" +
        "            border: 2px solid #5c5c5c;\n" +
        "            color: #ffffff;\n" +
        "            padding: 10px 14px;\n" +
        "            font-size: 12px;\n" +
        "            outline: none;\n" +
        "            text-shadow: 2px 2px 0px #222;\n" +
        "            border-radius: 0;\n" +
        "        }\n" +
        "        .input-field:focus {\n" +
        "            border-color: #ffffff;\n" +
        "        }\n" +
        "        .nick-input {\n" +
        "            flex: 1;\n" +
        "            max-width: 200px;\n" +
        "        }\n" +
        "        .messages-area {\n" +
        "            flex: 1;\n" +
        "            flex-shrink: 1;\n" +
        "            min-height: 0;\n" +
        "            overflow-y: auto;\n" +
        "            padding: 20px;\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            gap: 8px;\n" +
        "            background: rgba(0, 0, 0, 0.35);\n" +
        "        }\n" +
        "        .messages-area::-webkit-scrollbar {\n" +
        "            width: 8px;\n" +
        "        }\n" +
        "        .messages-area::-webkit-scrollbar-thumb {\n" +
        "            background: #5c5c5c;\n" +
        "            border: 2px solid #000;\n" +
        "        }\n" +
        "        .msg-row {\n" +
        "            font-size: 12px;\n" +
        "            line-height: 1.6;\n" +
        "            word-break: break-word;\n" +
        "            text-shadow: 2px 2px 0px #1e1e1e;\n" +
        "            padding: 6px 10px;\n" +
        "            background: rgba(255, 255, 255, 0.02);\n" +
        "            border-left: 3px solid #5555ff;\n" +
        "        }\n" +
        "        .msg-row.self-msg {\n" +
        "            border-left-color: #ffaa00;\n" +
        "            background: rgba(255, 170, 0, 0.02);\n" +
        "        }\n" +
        "        .msg-row.system-msg {\n" +
        "            border-left-color: #ff5555;\n" +
        "            background: rgba(255, 85, 85, 0.04);\n" +
        "            font-style: italic;\n" +
        "        }\n" +
        "        .sender-name {\n" +
        "            text-decoration: none;\n" +
        "        }\n" +
        "        .chat-image {\n" +
        "            max-width: 100%;\n" +
        "            max-height: 200px;\n" +
        "            border: 2px solid #5c5c5c;\n" +
        "            margin-top: 6px;\n" +
        "            display: block;\n" +
        "            cursor: zoom-in;\n" +
        "        }\n" +
        "        .chat-image:hover {\n" +
        "            border-color: #ffffff;\n" +
        "        }\n" +
        "        .msg-time {\n" +
        "            color: #777777;\n" +
        "            margin-right: 8px;\n" +
        "            font-size: 10px;\n" +
        "        }\n" +
        "        .input-pane {\n" +
        "            flex-shrink: 0;\n" +
        "            padding: 16px 20px;\n" +
        "            display: flex;\n" +
        "            gap: 8px;\n" +
        "            border-top: 4px solid #5c5c5c;\n" +
        "            background: rgba(0,0,0,0.4);\n" +
        "            z-index: 5;\n" +
        "            position: relative;\n" +
        "        }\n" +
        "        .message-input {\n" +
        "            flex: 1;\n" +
        "            min-width: 0;\n" +
        "        }\n" +
        "        \n" +
        "        .emoji-picker {\n" +
        "            position: absolute;\n" +
        "            bottom: 75px;\n" +
        "            left: 20px;\n" +
        "            background: var(--mc-dark-bg);\n" +
        "            border: 3px solid var(--mc-purple-border);\n" +
        "            box-shadow: 0 0 0 3px var(--mc-purple-shadow);\n" +
        "            padding: 8px;\n" +
        "            display: grid;\n" +
        "            grid-template-columns: repeat(4, 1fr);\n" +
        "            gap: 8px;\n" +
        "            z-index: 100;\n" +
        "        }\n" +
        "        .emoji-picker span {\n" +
        "            font-size: 18px;\n" +
        "            cursor: pointer;\n" +
        "            text-align: center;\n" +
        "            user-select: none;\n" +
        "        }\n" +
        "        .emoji-picker span:hover {\n" +
        "            transform: scale(1.25);\n" +
        "        }\n" +
        "        \n" +
        "        .btn {\n" +
        "            background: var(--mc-gray-btn);\n" +
        "            border-top: 2px solid var(--mc-border-light);\n" +
        "            border-left: 2px solid var(--mc-border-light);\n" +
        "            border-right: 2px solid var(--mc-border-dark);\n" +
        "            border-bottom: 2px solid var(--mc-border-dark);\n" +
        "            color: #e0e0e0;\n" +
        "            padding: 10px 16px;\n" +
        "            font-size: 12px;\n" +
        "            cursor: pointer;\n" +
        "            outline: none;\n" +
        "            text-shadow: 2px 2px 0px #000;\n" +
        "            border-radius: 0;\n" +
        "            flex-shrink: 0;\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            justify-content: center;\n" +
        "        }\n" +
        "        .btn:hover {\n" +
        "            background: var(--mc-btn-hover);\n" +
        "            color: #ffffa0;\n" +
        "            border-top: 2px solid #ffffff;\n" +
        "            border-left: 2px solid #ffffff;\n" +
        "            border-right: 2px solid #3c3c3c;\n" +
        "            border-bottom: 2px solid #3c3c3c;\n" +
        "        }\n" +
        "        .btn:active {\n" +
        "            background: var(--mc-btn-active);\n" +
        "            border-top: 2px solid var(--mc-border-dark);\n" +
        "            border-left: 2px solid var(--mc-border-dark);\n" +
        "            border-right: 2px solid var(--mc-border-light);\n" +
        "            border-bottom: 2px solid var(--mc-border-light);\n" +
        "            color: #aaaaaa;\n" +
        "        }\n" +
        "        \n" +
        "        .sidebar {\n" +
        "            position: absolute;\n" +
        "            top: 68px;\n" +
        "            right: -260px;\n" +
        "            width: 260px;\n" +
        "            height: calc(100% - 68px);\n" +
        "            background: var(--mc-dark-bg);\n" +
        "            border-left: 4px solid var(--mc-purple-border);\n" +
        "            box-shadow: -4px 0px 0px var(--mc-purple-shadow);\n" +
        "            transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1);\n" +
        "            z-index: 20;\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            padding: 20px;\n" +
        "            gap: 16px;\n" +
        "        }\n" +
        "        .sidebar.open {\n" +
        "            right: 0;\n" +
        "        }\n" +
        "        \n" +
        "        .left-sidebar {\n" +
        "            left: -260px;\n" +
        "            right: auto;\n" +
        "            border-left: none;\n" +
        "            border-right: 4px solid var(--mc-purple-border);\n" +
        "            box-shadow: 4px 0px 0px var(--mc-purple-shadow);\n" +
        "            transition: left 0.3s cubic-bezier(0.16, 1, 0.3, 1);\n" +
        "        }\n" +
        "        .left-sidebar.open {\n" +
        "            left: 0;\n" +
        "        }\n" +
        "        \n" +
        "        .sidebar-header {\n" +
        "            font-size: 13px;\n" +
        "            color: #ffff55;\n" +
        "            text-shadow: 2px 2px 0px #000;\n" +
        "            border-bottom: 2px solid #5c5c5c;\n" +
        "            padding-bottom: 10px;\n" +
        "            font-weight: normal;\n" +
        "        }\n" +
        "        .player-list {\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            gap: 10px;\n" +
        "            overflow-y: auto;\n" +
        "            flex: 1;\n" +
        "        }\n" +
        "        .player-list::-webkit-scrollbar {\n" +
        "            width: 6px;\n" +
        "        }\n" +
        "        .player-list::-webkit-scrollbar-thumb {\n" +
        "            background: #5c5c5c;\n" +
        "            border: 1px solid #000;\n" +
        "        }\n" +
        "        .player-row {\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            gap: 12px;\n" +
        "            padding: 8px 10px;\n" +
        "            background: rgba(0,0,0,0.3);\n" +
        "            border: 2px solid #5c5c5c;\n" +
        "        }\n" +
        "        .player-row.clickable {\n" +
        "            cursor: pointer;\n" +
        "        }\n" +
        "        .player-row.clickable:hover {\n" +
        "            border-color: #ffffff;\n" +
        "            background: rgba(255,255,255,0.05);\n" +
        "        }\n" +
        "        .player-avatar {\n" +
        "            width: 24px;\n" +
        "            height: 24px;\n" +
        "            border: 2px solid var(--mc-border-light);\n" +
        "            object-fit: cover;\n" +
        "            image-rendering: pixelated;\n" +
        "            background-color: #555;\n" +
        "        }\n" +
        "        .player-name {\n" +
        "            font-size: 11px;\n" +
        "            text-shadow: 2px 2px 0px #000;\n" +
        "            color: #ffffff;\n" +
        "            white-space: nowrap;\n" +
        "            overflow: hidden;\n" +
        "            text-overflow: ellipsis;\n" +
        "        }\n" +
        "        \n" +
        "        @media (max-width: 532px) {\n" +
        "            .chat-container {\n" +
        "                margin: 0;\n" +
        "                height: 100%;\n" +
        "                max-height: 100%;\n" +
        "                border: none;\n" +
        "                box-shadow: none;\n" +
        "            }\n" +
        "            .sidebar {\n" +
        "                width: 100%;\n" +
        "                right: -100%;\n" +
        "                border-left: none;\n" +
        "                box-shadow: none;\n" +
        "            }\n" +
        "            .sidebar.open {\n" +
        "                right: 0;\n" +
        "            }\n" +
        "            .left-sidebar {\n" +
        "                width: 100%;\n" +
        "                left: -100%;\n" +
        "                border-right: none;\n" +
        "                box-shadow: none;\n" +
        "            }\n" +
        "            .left-sidebar.open {\n" +
        "                left: 0;\n" +
        "            }\n" +
        "        }\n" +
        "        \n" +
        "        /* Clicker styles */\n" +
        "        .clicker-modal {\n" +
        "            position: absolute;\n" +
        "            top: 0;\n" +
        "            left: 0;\n" +
        "            width: 100%;\n" +
        "            height: 100%;\n" +
        "            background: var(--mc-dark-bg);\n" +
        "            z-index: 30;\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            padding: 20px;\n" +
        "            gap: 16px;\n" +
        "            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);\n" +
        "            transform: translateY(100%);\n" +
        "        }\n" +
        "        .clicker-modal.open {\n" +
        "            transform: translateY(0);\n" +
        "        }\n" +
        "        .clicker-layout {\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            gap: 16px;\n" +
        "            flex: 1;\n" +
        "            overflow-y: auto;\n" +
        "        }\n" +
        "        .clicker-layout::-webkit-scrollbar {\n" +
        "            width: 6px;\n" +
        "        }\n" +
        "        .clicker-layout::-webkit-scrollbar-thumb {\n" +
        "            background: #5c5c5c;\n" +
        "            border: 1px solid #000;\n" +
        "        }\n" +
        "        .clicker-section {\n" +
        "            background: rgba(0,0,0,0.3);\n" +
        "            border: 2px solid #5c5c5c;\n" +
        "            padding: 16px;\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            align-items: center;\n" +
        "            gap: 12px;\n" +
        "            position: relative;\n" +
        "        }\n" +
        "        .clicker-block-container {\n" +
        "            width: 100px;\n" +
        "            height: 100px;\n" +
        "            cursor: pointer;\n" +
        "            position: relative;\n" +
        "            transition: transform 0.05s ease;\n" +
        "            user-select: none;\n" +
        "            -webkit-user-drag: none;\n" +
        "        }\n" +
        "        .clicker-block-container:active {\n" +
        "            transform: scale(0.92);\n" +
        "        }\n" +
        "        .clicker-block-img {\n" +
        "            width: 100%;\n" +
        "            height: 100%;\n" +
        "            image-rendering: pixelated;\n" +
        "        }\n" +
        "        .clicker-progress-container {\n" +
        "            width: 100%;\n" +
        "            background: #555;\n" +
        "            border: 2px solid #000;\n" +
        "            height: 16px;\n" +
        "            position: relative;\n" +
        "        }\n" +
        "        .clicker-progress-bar {\n" +
        "            height: 100%;\n" +
        "            background: #55ff55;\n" +
        "            width: 0%;\n" +
        "            transition: width 0.1s ease;\n" +
        "        }\n" +
        "        .clicker-progress-text {\n" +
        "            position: absolute;\n" +
        "            top: 0;\n" +
        "            left: 0;\n" +
        "            width: 100%;\n" +
        "            height: 100%;\n" +
        "            display: flex;\n" +
        "            align-items: center;\n" +
        "            justify-content: center;\n" +
        "            font-size: 8px;\n" +
        "            color: #fff;\n" +
        "            text-shadow: 1px 1px 0px #000;\n" +
        "        }\n" +
        "        .clicker-inv-grid {\n" +
        "            display: grid;\n" +
        "            grid-template-columns: repeat(6, 1fr);\n" +
        "            gap: 8px;\n" +
        "            width: 100%;\n" +
        "        }\n" +
        "        .clicker-inv-slot {\n" +
        "            aspect-ratio: 1;\n" +
        "            background: #8b8b8b;\n" +
        "            border-top: 2px solid #373737;\n" +
        "            border-left: 2px solid #373737;\n" +
        "            border-right: 2px solid #fff;\n" +
        "            border-bottom: 2px solid #fff;\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            align-items: center;\n" +
        "            justify-content: center;\n" +
        "            position: relative;\n" +
        "            cursor: pointer;\n" +
        "            padding: 4px;\n" +
        "        }\n" +
        "        .clicker-inv-slot:hover {\n" +
        "            background: #9c9c9c;\n" +
        "            border-color: #fff #fff #373737 #373737;\n" +
        "        }\n" +
        "        .clicker-inv-slot.selected {\n" +
        "            border-color: #ffff55 !important;\n" +
        "            outline: 2px solid #ffff55;\n" +
        "        }\n" +
        "        .clicker-slot-icon {\n" +
        "            width: 32px;\n" +
        "            height: 32px;\n" +
        "            image-rendering: pixelated;\n" +
        "        }\n" +
        "        .clicker-slot-count {\n" +
        "            position: absolute;\n" +
        "            bottom: 2px;\n" +
        "            right: 4px;\n" +
        "            font-size: 8px;\n" +
        "            color: #fff;\n" +
        "            text-shadow: 1px 1px 0px #000;\n" +
        "        }\n" +
        "        .floating-hit {\n" +
        "            position: absolute;\n" +
        "            color: #ff5555;\n" +
        "            font-size: 10px;\n" +
        "            font-weight: bold;\n" +
        "            pointer-events: none;\n" +
        "            text-shadow: 1px 1px 0px #000;\n" +
        "            animation: floatUp 0.6s ease-out forwards;\n" +
        "            z-index: 10;\n" +
        "        }\n" +
        "        @keyframes floatUp {\n" +
        "            0% { transform: translateY(0) scale(1); opacity: 1; }\n" +
        "            100% { transform: translateY(-40px) scale(0.8); opacity: 0; }\n" +
        "        }\n" +
        "        .transfer-panel {\n" +
        "            width: 100%;\n" +
        "            display: flex;\n" +
        "            flex-direction: column;\n" +
        "            gap: 8px;\n" +
        "            background: rgba(0,0,0,0.5);\n" +
        "            padding: 12px;\n" +
        "            border: 2px solid #5c5c5c;\n" +
        "        }\n" +
        "        .transfer-panel h3 {\n" +
        "            font-size: 9px;\n" +
        "            color: #ffff55;\n" +
        "            margin-bottom: 4px;\n" +
        "            font-weight: normal;\n" +
        "        }\n" +
        "        .select-field {\n" +
        "            background: #000;\n" +
        "            border: 2px solid #5c5c5c;\n" +
        "            color: #fff;\n" +
        "            padding: 8px;\n" +
        "            font-size: 9px;\n" +
        "            outline: none;\n" +
        "            width: 100%;\n" +
        "            cursor: pointer;\n" +
        "            border-radius: 0;\n" +
        "        }\n" +
        "        \n" +
        "        @media (max-width: 532px) {\n" +
        "            .clicker-modal {\n" +
        "                width: 100%;\n" +
        "                height: 100%;\n" +
        "            }\n" +
        "        }\n" +
        "    </style>\n";

    private static final String INDEX_HTML_PART2 = 
        "   <script>\n" +
        "       function disconnectOld(oldNick) {\n" +
        "           if (!oldNick) return;\n" +
        "           fetch('/leave?nick=' + encodeURIComponent(oldNick), { method: 'POST', keepalive: true });\n" +
        "       }\n" +
        "       window.addEventListener('beforeunload', () => {\n" +
        "           const nick = document.getElementById('nick-input').value.trim();\n" +
        "           disconnectOld(nick);\n" +
        "       });\n" +
        "   </script>\n" +
        "</head>\n" +
        "<body>\n" +
        "    <div class=\"panorama-bg\"></div>\n" +
        "    <div class=\"chat-container\">\n" +
        "        <div class=\"header\">\n" +
        "            <div class=\"server-title-container\">\n" +
        "                <img src=\"/server-icon.png\" class=\"server-icon\" id=\"srv-icon\" alt=\"[Icon]\">\n" +
        "                <h1 id=\"server-name\">A Minecraft Server</h1>\n" +
        "            </div>\n" +
        "            <div class=\"header-actions\">\n" +
        "                <button class=\"btn\" id=\"toggle-sidebar-btn\" style=\"padding: 4px 10px; font-size: 10px;\">Players (0)</button>\n" +
        "                <div class=\"status\" id=\"status-panel\">\n" +
        "                    <span class=\"status-dot\"></span>\n" +
        "                    <span id=\"status-text\">...</span>\n" +
        "                </div>\n" +
        "            </div>\n" +
        "        </div>\n" +
        "        \n" +
        "        <!-- Creative Tabs Bar -->\n" +
        "        <div class=\"tabs-bar\" id=\"tabs-bar\">\n" +
        "            <div class=\"tab active\" data-target=\"global\" id=\"tab-global\">Chat</div>\n" +
        "        </div>\n" +
        "        \n" +
        "        <div class=\"setup-pane\">\n" +
        "            <input type=\"file\" id=\"avatar-input\" style=\"display:none;\" accept=\"image/png,image/jpeg,image/gif\">\n" +
        "            <div class=\"my-avatar-wrapper\" id=\"avatar-wrapper\" title=\"Click to change avatar\">\n" +
        "                <img class=\"my-avatar\" id=\"my-avatar\" src=\"data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22 fill=%22%23888888%22><path d=%22M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z%22/></svg>\" alt=\"\">\n" +
        "                <span class=\"my-avatar-badge\">✎</span>\n" +
        "            </div>\n" +
        "            <input type=\"text\" class=\"input-field nick-input\" id=\"nick-input\" placeholder=\"Nickname\" maxlength=\"16\">\n" +
        "            <button class=\"btn\" id=\"open-clicker-btn\" style=\"padding: 10px 14px; font-size: 14px;\" title=\"Clicker Mini-game\">⛏️</button>\n" +
        "            <select id=\"lang-select\" style=\"padding: 10px 8px; font-size: 10px; cursor: pointer; border-radius: 0; outline: none; margin-left: 4px; background: var(--mc-gray-btn); color: white; border-top: 2px solid var(--mc-border-light); border-left: 2px solid var(--mc-border-light); border-right: 2px solid var(--mc-border-dark); border-bottom: 2px solid var(--mc-border-dark); font-family: inherit;\">\n" +
        "                <option value=\"en\">EN</option>\n" +
        "                <option value=\"ru\">RU</option>\n" +
        "            </select>\n" +
        "        </div>\n" +
        "        <div class=\"messages-area\" id=\"messages-area\">\n" +
        "        </div>\n" +
        "        <form class=\"input-pane\" id=\"chat-form\">\n" +
        "            <input type=\"file\" id=\"file-input\" style=\"display:none;\" accept=\"image/*,image/gif\">\n" +
        "            <button type=\"button\" class=\"btn\" id=\"attach-btn\" style=\"padding: 10px 14px; font-size: 12px;\" title=\"Attach image\">📎</button>\n" +
        "            <button type=\"button\" class=\"btn\" id=\"emoji-btn\" style=\"padding: 10px 14px; font-size: 12px;\" title=\"Emojis\">😀</button>\n" +
        "            \n" +
        "            <div class=\"emoji-picker\" id=\"emoji-picker\" style=\"display:none;\">\n" +
        "                <span>😀</span><span>😂</span><span>😊</span><span>😍</span>\n" +
        "                <span>👍</span><span>👎</span><span>🔥</span><span>💩</span>\n" +
        "                <span>👏</span><span>🎉</span><span>🚀</span><span>❤️</span>\n" +
        "                <span>👀</span><span>🌟</span><span>🎮</span><span>🎯</span>\n" +
        "            </div>\n" +
        "            \n" +
        "            <input type=\"text\" class=\"input-field message-input\" id=\"msg-input\" placeholder=\"Write a message...\" autocomplete=\"off\" maxlength=\"100\">\n" +
        "            <button type=\"submit\" class=\"btn\" id=\"send-btn\">Send</button>\n" +
        "        </form>\n" +
        "        \n" +
        "        <!-- Right players list sidebar -->\n" +
        "        <div class=\"sidebar\" id=\"sidebar\">\n" +
        "            <h2 class=\"sidebar-header\" id=\"sidebar-title\">Online Players</h2>\n" +
        "            <div class=\"player-list\" id=\"player-list\">\n" +
        "            </div>\n" +
        "            <button class=\"btn\" id=\"close-sidebar-btn\" style=\"width: 100%;\">Close</button>\n" +
        "        </div>\n" +
        "        \n" +
        "        <!-- Left chats list sidebar -->\n" +
        "        <div class=\"sidebar left-sidebar\" id=\"chats-sidebar\">\n" +
        "            <h2 class=\"sidebar-header\" id=\"chats-title\">Direct Messages</h2>\n" +
        "            <div class=\"player-list\" id=\"chats-list\">\n" +
        "            </div>\n" +
        "            <button class=\"btn\" id=\"close-chats-btn\" style=\"width: 100%;\">Close</button>\n" +
        "        </div>\n" +
        "        \n" +
        "        <!-- Clicker Mini-game Modal -->\n" +
        "        <div class=\"clicker-modal\" id=\"clicker-modal\">\n" +
        "            <h2 class=\"sidebar-header\" id=\"clicker-title\" style=\"text-align: center; border-bottom: none; padding-bottom: 0;\">Clicker Mine ⛏️</h2>\n" +
        "            \n" +
        "            <div class=\"clicker-layout\">\n" +
        "                <!-- Mining Section -->\n" +
        "                <div class=\"clicker-section\">\n" +
        "                    <div class=\"clicker-block-container\" id=\"clicker-block\">\n" +
        "                        <img class=\"clicker-block-img\" id=\"clicker-block-img\" src=\"\" alt=\"Block\">\n" +
        "                    </div>\n" +
        "                    <div class=\"clicker-progress-container\">\n" +
        "                        <div class=\"clicker-progress-bar\" id=\"clicker-progress-bar\"></div>\n" +
        "                        <div class=\"clicker-progress-text\" id=\"clicker-progress-text\">0 / 0</div>\n" +
        "                    </div>\n" +
        "                </div>\n" +
        "                \n" +
        "                <!-- Inventory Section -->\n" +
        "                <div class=\"clicker-section\" style=\"gap: 8px; align-items: stretch;\">\n" +
        "                    <h3 id=\"clicker-stock-title\" style=\"font-size: 9px; color: #aaaaaa; text-align: center;\">Your Stock:</h3>\n" +
        "                    <div class=\"clicker-inv-grid\" id=\"clicker-inv-grid\">\n" +
        "                    </div>\n" +
        "                </div>\n" +
        "\n" +
        "                <!-- Transfer Panel -->\n" +
        "                <div class=\"transfer-panel\" id=\"transfer-panel\" style=\"display: none;\">\n" +
        "                    <h3 id=\"transfer-panel-title\">Transfer <span id=\"transfer-ore-name\" style=\"color: #ffff55;\">ore</span> to player on server:</h3>\n" +
        "                    <select class=\"select-field\" id=\"transfer-player-select\">\n" +
        "                        <option value=\"\">Select player...</option>\n" +
        "                    </select>\n" +
        "                    <div style=\"display: flex; align-items: center; gap: 8px; margin-top: 4px;\">\n" +
        "                        <span id=\"transfer-amount-label\" style=\"font-size: 8px; color: #aaa; white-space: nowrap;\">Amount:</span>\n" +
        "                        <input type=\"number\" class=\"select-field\" id=\"transfer-amount-input\" value=\"1\" min=\"1\" style=\"width: 80px; padding: 4px;\">\n" +
        "                        <button type=\"button\" class=\"btn\" id=\"transfer-max-btn\" style=\"padding: 4px 8px; font-size: 8px; margin: 0;\">MAX</button>\n" +
        "                    </div>\n" +
        "                    <button type=\"button\" class=\"btn\" id=\"transfer-send-btn\" style=\"margin-top: 4px;\">Send resources</button>\n" +
        "                </div>\n" +
            "            </div>\n" +
            "            \n" +
            "            <button class=\"btn\" id=\"close-clicker-btn\" style=\"width: 100%;\">Back to chat</button>\n" +
            "        </div>\n" +
            "        </div>\n" +
            "    </div>\n" +
        "    <script>\n" +
        "        const messagesArea = document.getElementById('messages-area');\n" +
        "        const nickInput = document.getElementById('nick-input');\n" +
        "        const msgInput = document.getElementById('msg-input');\n" +
        "        const chatForm = document.getElementById('chat-form');\n" +
        "        const statusPanel = document.getElementById('status-panel');\n" +
        "        const statusText = document.getElementById('status-text');\n" +
        "        const serverName = document.getElementById('server-name');\n" +
        "        const srvIcon = document.getElementById('srv-icon');\n" +
        "        \n" +
        "        const sidebar = document.getElementById('sidebar');\n" +
        "        const toggleSidebarBtn = document.getElementById('toggle-sidebar-btn');\n" +
        "        const closeSidebarBtn = document.getElementById('close-sidebar-btn');\n" +
        "        const playerList = document.getElementById('player-list');\n" +
        "        \n" +
        "        const chatsSidebar = document.getElementById('chats-sidebar');\n" +
        "        const chatsList = document.getElementById('chats-list');\n" +
        "        const closeChatsBtn = document.getElementById('close-chats-btn');\n" +
        "        \n" +
        "        const tabsBar = document.getElementById('tabs-bar');\n" +
        "        const fileInput = document.getElementById('file-input');\n" +
        "        const attachBtn = document.getElementById('attach-btn');\n" +
        "        const emojiBtn = document.getElementById('emoji-btn');\n" +
        "        const emojiPicker = document.getElementById('emoji-picker');\n" +
        "        const avatarInput = document.getElementById('avatar-input');\n" +
        "        const avatarWrapper = document.getElementById('avatar-wrapper');\n" +
        "        const myAvatar = document.getElementById('my-avatar');\n" +
        "        const langSelect = document.getElementById('lang-select');\n" +
        "        \n" +
        "        let activeTab = 'global';\n" +
        "        let globalMessages = [];\n" +
        "        let pmMessages = {};\n" +
        "        \n" +
        "        const i18n = {\n" +
        "            en: {\n" +
        "                players: \"Players\",\n" +
        "                chat: \"Chat\",\n" +
        "                clickToChangeAvatar: \"Click to change avatar\",\n" +
        "                nickname: \"Nickname\",\n" +
        "                clickerMiniGame: \"Clicker Mini-game\",\n" +
        "                attachImage: \"Attach image\",\n" +
        "                emojis: \"Emojis\",\n" +
        "                writeMessage: \"Write a message...\",\n" +
        "                send: \"Send\",\n" +
        "                onlinePlayers: \"Online Players\",\n" +
        "                close: \"Close\",\n" +
        "                directMessages: \"Direct Messages\",\n" +
        "                clickerMine: \"Clicker Mine ⛏️\",\n" +
        "                yourStock: \"Your Stock:\",\n" +
        "                transferOre: \"Transfer %ore% to player on server:\",\n" +
        "                selectPlayer: \"Select player...\",\n" +
        "                amount: \"Amount:\",\n" +
        "                sendResources: \"Send resources\",\n" +
        "                backToChat: \"Back to chat\",\n" +
        "                connecting: \"Connecting...\",\n" +
        "                connected: \"Connected\",\n" +
        "                errorStatus: \"Error\",\n" +
        "                enterNick: \"Please enter a nickname first\",\n" +
        "                invalidAmount: \"Please specify a correct amount!\",\n" +
        "                notEnoughResources: \"Not enough resources in stock!\",\n" +
        "                transferSuccess: \"Resources successfully sent to player!\",\n" +
        "                transferError: \"Error\",\n" +
        "                sending: \"Sending...\",\n" +
        "                clickToView: \"Click to open image\",\n" +
        "                writePM: \"Write direct message\",\n" +
        "                pmWith: \"DM: \",\n" +
        "                noPlayers: \"No players online\",\n" +
        "                noChats: \"No direct messages\",\n" +
        "                errorUploading: \"Upload error\"\n" +
        "            },\n" +
        "            ru: {\n" +
        "                players: \"Игроки\",\n" +
        "                chat: \"Чат\",\n" +
        "                clickToChangeAvatar: \"Нажмите, чтобы сменить аватарку\",\n" +
        "                nickname: \"Никнейм\",\n" +
        "                clickerMiniGame: \"Мини-игра Кликер\",\n" +
        "                attachImage: \"Прикрепить изображение\",\n" +
        "                emojis: \"Смайлики\",\n" +
        "                writeMessage: \"Написать сообщение...\",\n" +
        "                send: \"Отправить\",\n" +
        "                onlinePlayers: \"Игроки в сети\",\n" +
        "                close: \"Назад\",\n" +
        "                directMessages: \"Переписки\",\n" +
        "                clickerMine: \"Шахта Кликер ⛏️\",\n" +
        "                yourStock: \"Ваш склад:\",\n" +
        "                transferOre: \"Передать %ore% игроку на сервере:\",\n" +
        "                selectPlayer: \"Выберите игрока...\",\n" +
        "                amount: \"Количество:\",\n" +
        "                sendResources: \"Отправить ресурсы\",\n" +
        "                backToChat: \"Назад в чат\",\n" +
        "                connecting: \"Подключение...\",\n" +
        "                connected: \"В сети\",\n" +
        "                errorStatus: \"Ошибка\",\n" +
        "                enterNick: \"Сначала введите никнейм!\",\n" +
        "                invalidAmount: \"Укажите корректное количество!\",\n" +
        "                notEnoughResources: \"Недостаточно ресурсов на складе!\",\n" +
        "                transferSuccess: \"Ресурсы успешно отправлены игроку!\",\n" +
        "                transferError: \"Ошибка\",\n" +
        "                sending: \"Отправка...\",\n" +
        "                clickToView: \"Нажмите, чтобы открыть\",\n" +
        "                writePM: \"Написать личное сообщение\",\n" +
        "                pmWith: \"ЛС: \",\n" +
        "                noPlayers: \"Никого нет\",\n" +
        "                noChats: \"Нет переписок\",\n" +
        "                errorUploading: \"Ошибка загрузки\"\n" +
        "            }\n" +
        "        };\n" +
        "\n" +
        "        let currentLang = localStorage.getItem('mc_chat_lang') || 'en';\n" +
        "\n" +
        "        function updateLanguageUI() {\n" +
        "            const lang = currentLang;\n" +
        "            localStorage.setItem('mc_chat_lang', lang);\n" +
        "            langSelect.value = lang;\n" +
        "            \n" +
        "            document.getElementById('tab-global').textContent = i18n[lang].chat;\n" +
        "            avatarWrapper.title = i18n[lang].clickToChangeAvatar;\n" +
        "            nickInput.placeholder = i18n[lang].nickname;\n" +
        "            openClickerBtn.title = i18n[lang].clickerMiniGame;\n" +
        "            attachBtn.title = i18n[lang].attachImage;\n" +
        "            emojiBtn.title = i18n[lang].emojis;\n" +
        "            msgInput.placeholder = i18n[lang].writeMessage;\n" +
        "            \n" +
        "            const sendBtn = document.getElementById('send-btn');\n" +
        "            if (sendBtn.textContent !== '...' && sendBtn.textContent !== 'Sending...' && sendBtn.textContent !== 'Отправка...') {\n" +
        "                sendBtn.textContent = i18n[lang].send;\n" +
        "            }\n" +
        "            \n" +
        "            document.getElementById('sidebar-title').textContent = i18n[lang].onlinePlayers;\n" +
        "            closeSidebarBtn.textContent = i18n[lang].close;\n" +
        "            document.getElementById('chats-title').textContent = i18n[lang].directMessages;\n" +
        "            closeChatsBtn.textContent = i18n[lang].close;\n" +
        "            document.getElementById('clicker-title').textContent = i18n[lang].clickerMine;\n" +
        "            document.getElementById('clicker-stock-title').textContent = i18n[lang].yourStock;\n" +
        "            \n" +
        "            let oreSpan = `<span id=\"transfer-ore-name\" style=\"color: #ffff55;\">${selectedOreSlot ? (serverOresList.find(o => o.id === selectedOreSlot)?.name || selectedOreSlot) : 'ore'}</span>`;\n" +
        "            document.getElementById('transfer-panel-title').innerHTML = i18n[lang].transferOre.replace('%ore%', oreSpan);\n" +
        "            \n" +
        "            document.getElementById('transfer-amount-label').textContent = i18n[lang].amount;\n" +
        "            transferSendBtn.textContent = i18n[lang].sendResources;\n" +
        "            closeClickerBtn.textContent = i18n[lang].backToChat;\n" +
        "            \n" +
        "            // Image titles\n" +
        "            document.querySelectorAll('.chat-image').forEach(img => img.title = i18n[lang].clickToView);\n" +
        "            \n" +
        "            // Senders title\n" +
        "            document.querySelectorAll('.sender-name').forEach(s => {\n" +
        "                if (s.style.cursor === 'pointer') {\n" +
        "                    s.title = i18n[lang].writePM;\n" +
        "                }\n" +
        "            });\n" +
        "            \n" +
        "            // Tab titles\n" +
        "            document.querySelectorAll('.tab').forEach(t => {\n" +
        "                const target = t.getAttribute('data-target');\n" +
        "                if (target && target.startsWith('pm-')) {\n" +
        "                    const cleanNick = target.replace('pm-', '');\n" +
        "                    t.childNodes[0].nodeValue = `${i18n[lang].pmWith}${cleanNick} `;\n" +
        "                }\n" +
        "            });\n" +
        "            \n" +
        "            // Status panel text\n" +
        "            if (statusPanel.className.includes('connecting')) {\n" +
        "                statusText.textContent = (statusText.textContent === '...' ? '...' : i18n[lang].connecting);\n" +
        "            } else {\n" +
        "                statusText.textContent = i18n[lang].connected;\n" +
        "            }\n" +
        "            \n" +
        "            // Re-render select option\n" +
        "            if (transferPlayerSelect.options.length > 0) {\n" +
        "                transferPlayerSelect.options[0].textContent = i18n[lang].selectPlayer;\n" +
        "            }\n" +
        "            \n" +
        "            updateToggleSidebarBtnText();\n" +
        "        }\n" +
        "\n" +
        "        function updateToggleSidebarBtnText(online = null, max = null) {\n" +
        "            if (online !== null && max !== null) {\n" +
        "                window.lastOnlineCount = online;\n" +
        "                window.lastMaxPlayers = max;\n" +
        "            }\n" +
        "            const o = window.lastOnlineCount !== undefined ? window.lastOnlineCount : 0;\n" +
        "            const m = window.lastMaxPlayers !== undefined ? window.lastMaxPlayers : 20;\n" +
        "            toggleSidebarBtn.textContent = `${i18n[currentLang].players} (${o}/${m})`;\n" +
        "        }\n" +
        "        \n" +
        "        const savedNick = localStorage.getItem('mc_chat_nick');\n" +
        "        if (savedNick) {\n" +
        "            nickInput.value = savedNick;\n" +
        "        } else {\n" +
        "            nickInput.value = 'WebPlayer' + Math.floor(Math.random() * 1000);\n" +
        "            localStorage.setItem('mc_chat_nick', nickInput.value);\n" +
        "        }\n" +
        "\n" +
        "        nickInput.addEventListener('change', () => {\n" +
        "            const oldNick = localStorage.getItem('mc_chat_nick');\n" +
        "            const newNick = nickInput.value.trim();\n" +
        "            if (newNick && newNick !== oldNick) {\n" +
        "                disconnectOld(oldNick);\n" +
        "                localStorage.setItem('mc_chat_nick', newNick);\n" +
        "                connectSSE();\n" +
        "                loadPrivateHistory();\n" +
        "                loadMyAvatar();\n" +
        "            }\n" +
        "        });\n" +
        "        \n" +
        "        toggleSidebarBtn.addEventListener('click', () => {\n" +
        "            sidebar.classList.toggle('open');\n" +
        "            chatsSidebar.classList.remove('open');\n" +
        "        });\n" +
        "        \n" +
        "        closeSidebarBtn.addEventListener('click', () => {\n" +
        "            sidebar.classList.remove('open');\n" +
        "        });\n" +
        "        \n" +
        "        srvIcon.addEventListener('click', (e) => {\n" +
        "            e.stopPropagation();\n" +
        "            renderChatsList();\n" +
        "            chatsSidebar.classList.toggle('open');\n" +
        "            sidebar.classList.remove('open');\n" +
        "        });\n" +
        "        \n" +
        "        closeChatsBtn.addEventListener('click', () => {\n" +
        "            chatsSidebar.classList.remove('open');\n" +
        "        });\n" +
        "        \n" +
        "        langSelect.addEventListener('change', () => {\n" +
        "            currentLang = langSelect.value;\n" +
        "            updateLanguageUI();\n" +
        "            if (chatsSidebar.classList.contains('open')) renderChatsList();\n" +
        "            if (sidebar.classList.contains('open')) loadPlayers();\n" +
        "        });\n" +
        "        \n" +
        "        avatarWrapper.addEventListener('click', () => avatarInput.click());\n" +
        "        avatarInput.addEventListener('change', () => {\n" +
        "            const file = avatarInput.files[0];\n" +
        "            if (!file) return;\n" +
        "            const nick = nickInput.value.trim();\n" +
        "            if (!nick) { alert(i18n[currentLang].enterNick); return; }\n" +
        "            fetch('/avatar/upload?nick=' + encodeURIComponent(nick), {\n" +
        "                method: 'POST',\n" +
        "                body: file\n" +
        "            })\n" +
        "            .then(res => res.json())\n" +
        "            .then(data => {\n" +
        "                avatarInput.value = '';\n" +
        "                myAvatar.src = '/avatar/' + nick + '?t=' + Date.now();\n" +
        "                loadPlayers();\n" +
        "            })\n" +
        "            .catch(err => {\n" +
        "                avatarInput.value = '';\n" +
        "                console.error('Avatar upload error', err);\n" +
        "            });\n" +
        "        });\n" +
        "        \n" +
        "        function loadMyAvatar() {\n" +
        "            const nick = nickInput.value.trim();\n" +
        "            if (!nick) return;\n" +
        "            const testImg = new Image();\n" +
        "            testImg.onload = () => { myAvatar.src = '/avatar/' + nick + '?t=' + Date.now(); };\n" +
        "            testImg.onerror = () => {};\n" +
        "            testImg.src = '/avatar/' + nick + '?t=' + Date.now();\n" +
        "        }\n" +
        "        \n" +
        "        const openClickerBtn = document.getElementById('open-clicker-btn');\n" +
        "        const closeClickerBtn = document.getElementById('close-clicker-btn');\n" +
        "        const clickerModal = document.getElementById('clicker-modal');\n" +
        "        const clickerBlock = document.getElementById('clicker-block');\n" +
        "        const clickerBlockImg = document.getElementById('clicker-block-img');\n" +
        "        const clickerProgressBar = document.getElementById('clicker-progress-bar');\n" +
        "        const clickerProgressText = document.getElementById('clicker-progress-text');\n" +
        "        \n" +
        "        const transferPanel = document.getElementById('transfer-panel');\n" +
        "        const transferOreName = document.getElementById('transfer-ore-name');\n" +
        "        const transferPlayerSelect = document.getElementById('transfer-player-select');\n" +
        "        const transferSendBtn = document.getElementById('transfer-send-btn');\n" +
        "        const transferAmountInput = document.getElementById('transfer-amount-input');\n" +
        "        const transferMaxBtn = document.getElementById('transfer-max-btn');\n" +
        "        \n" +
        "        let clickerInventory = {};\n" +
        "        let selectedOreSlot = null;\n" +
        "        let currentOreType = \"\";\n" +
        "        let currentHits = 0;\n" +
        "        let maxHits = 0;\n" +
        "        let serverOresList = [];\n" +
        "        \n" +
        "        function adjustColor(hex, percent) {\n" +
        "            let num = parseInt(hex.replace(\"#\",\"\"), 16),\n" +
        "                amt = Math.round(2.55 * percent),\n" +
        "                R = (num >> 16) + amt,\n" +
        "                G = (num >> 8 & 0x00FF) + amt,\n" +
        "                B = (num & 0x0000FF) + amt;\n" +
        "            return \"#\" + (0x1000000 + (R<255?R<0?0:R:255)*0x10000 + (G<255?G<0?0:G:255)*0x100 + (B<255?B<0?0:B:255)).toString(16).slice(1);\n" +
        "        }\n" +
        "        \n" +
        "        function getOreSvgUrl(oreType, hits, maxHits) {\n" +
        "            let oreColor = \"#707070\";\n" +
        "            if (serverOresList) {\n" +
        "                const found = serverOresList.find(o => o.id === oreType);\n" +
        "                if (found) oreColor = found.color;\n" +
        "            }\n" +
        "            let palette = {};\n" +
        "            let grid = [];\n" +
        "            if (oreType === 'netherite') {\n" +
        "                palette = { '.': '#343034', 'x': '#242224', '#': '#443c44', 'o': '#4c3e38', 'w': '#5c4e48' };\n" +
        "                grid = [\n" +
        "                    'x','x','x','x','x','x','x','x',\n" +
        "                    'x','.','.','.','.','.','.','x',\n" +
        "                    'x','.','#','#','#','#','.','x',\n" +
        "                    'x','.','#','o','w','#','.','x',\n" +
        "                    'x','.','#','w','o','#','.','x',\n" +
        "                    'x','.','#','#','#','#','.','x',\n" +
        "                    'x','.','.','.','.','.','.','x',\n" +
        "                    'x','x','x','x','x','x','x','x'\n" +
        "                ];\n" +
        "            } else {\n" +
        "                const darkColor = adjustColor(oreColor, -35);\n" +
        "                const lightColor = adjustColor(oreColor, 25);\n" +
        "                palette = {\n" +
        "                    '.': '#707070',\n" +
        "                    'x': '#585858',\n" +
        "                    '#': darkColor,\n" +
        "                    'o': oreColor,\n" +
        "                    'w': lightColor\n" +
        "                };\n" +
        "                grid = [\n" +
        "                    '.','.','x','.','.','x','.','.',\n" +
        "                    '.','#','o','.','.','w','#','.',\n" +
        "                    'x','#','o','.','x','.','#','x',\n" +
        "                    '.','.','.','x','#','o','w','.',\n" +
        "                    '.','x','.','#','o','w','.','.',\n" +
        "                    '.','#','o','w','.','x','.','.',\n" +
        "                    'x','#','o','.','.','.','x','.',\n" +
        "                    '.','.','.','.','x','.','.','.'\n" +
        "                ];\n" +
        "            }\n" +
        "            let svg = `<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 8 8\" width=\"100%\" height=\"100%\" style=\"image-rendering:pixelated;\">`;\n" +
        "            for (let y = 0; y < 8; y++) {\n" +
        "                for (let x = 0; x < 8; x++) {\n" +
        "                    const char = grid[y * 8 + x];\n" +
        "                    const color = palette[char] || '#707070';\n" +
        "                    svg += `<rect x=\"${x}\" y=\"${y}\" width=\"1\" height=\"1\" fill=\"${color}\"/>`;\n" +
        "                }\n" +
        "            }\n" +
        "            const ratio = hits / maxHits;\n" +
        "            let crackPath = \"\";\n" +
        "            if (ratio >= 0.75) {\n" +
        "                crackPath = \"M 1 2 L 3 2 L 3 4 L 5 4 L 5 7 M 6 1 L 6 3 L 7 5 L 4 5\";\n" +
        "            } else if (ratio >= 0.5) {\n" +
        "                crackPath = \"M 1 2 L 3 2 L 3 4 L 5 4 M 6 1 L 6 3 L 7 5\";\n" +
        "            } else if (ratio >= 0.25) {\n" +
        "                crackPath = \"M 1 2 L 3 2 M 6 1 L 6 3\";\n" +
        "            }\n" +
        "            if (crackPath) {\n" +
        "                svg += `<path d=\"${crackPath}\" stroke=\"black\" stroke-width=\"0.5\" fill=\"none\" opacity=\"0.6\"/>`;\n" +
        "            }\n" +
        "            svg += `</svg>`;\n" +
        "            return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));\n" +
        "        }\n" +
        "        \n" +
        "        function rebuildInventoryGrid() {\n" +
        "            const grid = document.getElementById('clicker-inv-grid');\n" +
        "            grid.innerHTML = '';\n" +
        "            if (!serverOresList) return;\n" +
        "            serverOresList.forEach(ore => {\n" +
        "                const slot = document.createElement('div');\n" +
        "                slot.className = 'clicker-inv-slot';\n" +
        "                slot.setAttribute('data-ore', ore.id);\n" +
        "                slot.id = 'slot-' + ore.id;\n" +
        "                slot.title = ore.name;\n" +
        "                if (selectedOreSlot === ore.id) {\n" +
        "                    slot.classList.add('selected');\n" +
        "                }\n" +
        "                slot.addEventListener('click', () => selectOreSlot(ore.id));\n" +
        "                \n" +
        "                const img = document.createElement('img');\n" +
        "                img.className = 'clicker-slot-icon';\n" +
        "                img.id = 'icon-' + ore.id;\n" +
        "                img.src = getOreSvgUrl(ore.id, 0, 1);\n" +
        "                img.alt = ore.name;\n" +
        "                \n" +
        "                const countSpan = document.createElement('span');\n" +
        "                countSpan.className = 'clicker-slot-count';\n" +
        "                countSpan.id = 'count-' + ore.id;\n" +
        "                countSpan.textContent = clickerInventory[ore.id] || 0;\n" +
        "                \n" +
        "                slot.appendChild(img);\n" +
        "                slot.appendChild(countSpan);\n" +
        "                grid.appendChild(slot);\n" +
        "            });\n" +
        "        }\n" +
        "        \n" +
        "        function loadClickerStatus() {\n" +
        "            const nick = nickInput.value.trim();\n" +
        "            if (!nick) return;\n" +
        "            fetch('/clicker/status?nick=' + encodeURIComponent(nick))\n" +
        "                .then(res => res.json())\n" +
        "                .then(data => {\n" +
        "                    currentOreType = data.ore;\n" +
        "                    currentHits = data.hits;\n" +
        "                    maxHits = data.maxHits;\n" +
        "                    clickerInventory = data.inventory;\n" +
        "                    if (data.ores) {\n" +
        "                        serverOresList = data.ores;\n" +
        "                        rebuildInventoryGrid();\n" +
        "                    }\n" +
        "                    updateClickerUI();\n" +
        "                })\n" +
        "                .catch(err => console.error('Error loading clicker status', err));\n" +
        "        }\n" +
        "        \n" +
        "        function updateClickerUI() {\n" +
        "            clickerBlockImg.src = getOreSvgUrl(currentOreType, currentHits, maxHits);\n" +
        "            \n" +
        "            const percent = Math.min(100, Math.floor((currentHits / maxHits) * 100));\n" +
        "            clickerProgressBar.style.width = percent + '%';\n" +
        "            clickerProgressText.textContent = `${currentHits} / ${maxHits}`;\n" +
        "            \n" +
        "            if (serverOresList) {\n" +
        "                serverOresList.forEach(ore => {\n" +
        "                    const countSpan = document.getElementById('count-' + ore.id);\n" +
        "                    if (countSpan) {\n" +
        "                        countSpan.textContent = clickerInventory[ore.id] || 0;\n" +
        "                    }\n" +
        "                });\n" +
        "            }\n" +
        "            \n" +
        "            if (selectedOreSlot) {\n" +
        "                const count = clickerInventory[selectedOreSlot] || 0;\n" +
        "                if (count <= 0) {\n" +
        "                    transferPanel.style.display = 'none';\n" +
        "                    document.querySelectorAll('.clicker-inv-slot').forEach(s => s.classList.remove('selected'));\n" +
        "                    selectedOreSlot = null;\n" +
        "                }\n" +
        "            }\n" +
        "        }\n" +
        "        \n" +
        "        function clickBlock(e) {\n" +
        "            const nick = nickInput.value.trim();\n" +
        "            if (!nick) return;\n" +
        "            \n" +
        "            const rect = clickerBlock.getBoundingClientRect();\n" +
        "            const x = e.clientX - rect.left;\n" +
        "            const y = e.clientY - rect.top;\n" +
        "            \n" +
        "            const floater = document.createElement('span');\n" +
        "            floater.className = 'floating-hit';\n" +
        "            floater.textContent = '-1';\n" +
        "            floater.style.left = x + 'px';\n" +
        "            floater.style.top = y + 'px';\n" +
        "            clickerBlock.appendChild(floater);\n" +
        "            setTimeout(() => floater.remove(), 600);\n" +
        "            \n" +
        "            const params = new URLSearchParams();\n" +
        "            params.append('nick', nick);\n" +
        "            \n" +
        "            fetch('/clicker/click', {\n" +
        "                method: 'POST',\n" +
        "                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n" +
        "                body: params\n" +
        "            })\n" +
        "            .then(res => res.json())\n" +
        "            .then(data => {\n" +
        "                currentOreType = data.ore;\n" +
        "                currentHits = data.hits;\n" +
        "                maxHits = data.maxHits;\n" +
        "                clickerInventory = data.inventory;\n" +
        "                updateClickerUI();\n" +
        "            })\n" +
        "            .catch(err => console.error('Error clicking block', err));\n" +
        "        }\n" +
        "        \n" +
        "        function selectOreSlot(ore) {\n" +
        "            const count = clickerInventory[ore] || 0;\n" +
        "            if (count <= 0) return;\n" +
        "            \n" +
        "            document.querySelectorAll('.clicker-inv-slot').forEach(s => {\n" +
        "                if (s.getAttribute('data-ore') === ore) {\n" +
        "                    s.classList.add('selected');\n" +
        "                } else {\n" +
        "                    s.classList.remove('selected');\n" +
        "                }\n" +
        "            });\n" +
        "            \n" +
        "            selectedOreSlot = ore;\n" +
        "            let oreName = ore;\n" +
        "            if (serverOresList) {\n" +
        "                const found = serverOresList.find(o => o.id === ore);\n" +
        "                if (found) oreName = found.name;\n" +
        "            }\n" +
        "            transferOreName.textContent = oreName;\n" +
        "            transferAmountInput.value = 1;\n" +
        "            transferAmountInput.max = count;\n" +
        "            transferPanel.style.display = 'flex';\n" +
        "            \n" +
        "            fetch('/players')\n" +
        "                .then(res => res.json())\n" +
        "                .then(data => {\n" +
        "                    transferPlayerSelect.innerHTML = `<option value=\\\"\\\">${i18n[currentLang].selectPlayer}</option>`;\n" +
        "                    data.forEach(p => {\n" +
        "                        if (!p.isWeb) {\n" +
        "                            const opt = document.createElement('option');\n" +
        "                            opt.value = p.name;\n" +
        "                            opt.textContent = p.name;\n" +
        "                            transferPlayerSelect.appendChild(opt);\n" +
        "                        }\n" +
        "                    });\n" +
        "                });\n" +
        "        }\n" +
        "        \n" +
        "        function transferOre() {\n" +
        "            const nick = nickInput.value.trim();\n" +
        "            const toPlayer = transferPlayerSelect.value;\n" +
        "            if (!nick || !selectedOreSlot || !toPlayer) return;\n" +
        "            \n" +
        "            const amount = parseInt(transferAmountInput.value) || 1;\n" +
        "            const maxAvailable = clickerInventory[selectedOreSlot] || 0;\n" +
        "            if (amount < 1) {\n" +
        "                alert(i18n[currentLang].invalidAmount);\n" +
        "                return;\n" +
        "            }\n" +
        "            if (amount > maxAvailable) {\n" +
        "                alert(i18n[currentLang].notEnoughResources);\n" +
        "                return;\n" +
        "            }\n" +
        "            \n" +
        "            const params = new URLSearchParams();\n" +
        "            params.append('nick', nick);\n" +
        "            params.append('ore', selectedOreSlot);\n" +
        "            params.append('to', toPlayer);\n" +
        "            params.append('amount', amount);\n" +
        "            \n" +
        "            fetch('/clicker/transfer', {\n" +
        "                method: 'POST',\n" +
        "                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n" +
        "                body: params\n" +
        "            })\n" +
        "            .then(res => res.json())\n" +
        "            .then(data => {\n" +
        "                clickerInventory = data.inventory;\n" +
        "                if (data.success) {\n" +
        "                    alert(i18n[currentLang].transferSuccess);\n" +
        "                } else {\n" +
        "                    alert(i18n[currentLang].transferError + ': ' + data.error);\n" +
        "                }\n" +
        "                updateClickerUI();\n" +
        "            })\n" +
        "            .catch(err => console.error('Error transferring ore', err));\n" +
        "        }\n" +
        "        \n" +
        "        emojiBtn.addEventListener('click', (e) => {\n" +
        "            e.stopPropagation();\n" +
        "            emojiPicker.style.display = emojiPicker.style.display === 'none' ? 'grid' : 'none';\n" +
        "        });\n" +
        "        document.addEventListener('click', () => {\n" +
        "            emojiPicker.style.display = 'none';\n" +
        "        });\n" +
        "        emojiPicker.querySelectorAll('span').forEach(span => {\n" +
        "            span.addEventListener('click', (e) => {\n" +
        "                msgInput.value += e.target.textContent;\n" +
        "                msgInput.focus();\n" +
        "            });\n" +
        "        });\n" +
        "        \n" +
        "        attachBtn.addEventListener('click', () => fileInput.click());\n" +
        "        fileInput.addEventListener('change', () => {\n" +
        "            const file = fileInput.files[0];\n" +
        "            if (!file) return;\n" +
        "            \n" +
        "            const sendBtn = document.getElementById('send-btn');\n" +
        "            sendBtn.disabled = true;\n" +
        "            sendBtn.textContent = i18n[currentLang].sending;\n" +
        "            \n" +
        "            fetch('/upload?name=' + encodeURIComponent(file.name), {\n" +
        "                method: 'POST',\n" +
        "                body: file\n" +
        "            })\n" +
        "            .then(res => res.json())\n" +
        "            .then(data => {\n" +
        "                sendBtn.disabled = false;\n" +
        "                sendBtn.textContent = i18n[currentLang].send;\n" +
        "                fileInput.value = '';\n" +
        "                \n" +
        "                const imgTag = `[img]${data.url}[/img]`;\n" +
        "                sendMessage(imgTag);\n" +
        "            })\n" +
        "            .catch(err => {\n" +
        "                sendBtn.disabled = false;\n" +
        "                sendBtn.textContent = i18n[currentLang].send;\n" +
        "                fileInput.value = '';\n" +
        "                console.error(\"Upload error\", err);\n" +
        "                alert(\"Ошибка загрузки\");\n" +
        "            });\n" +
        "        });\n" +
        "\n" +
        "        function parseMinecraftColors(text) {\n" +
        "            if (!text) return \"\";\n" +
        "            const colorMap = {\n" +
        "                '0': '#000000', '1': '#0000aa', '2': '#00aa00', '3': '#00aaaa',\n" +
        "                '4': '#aa0000', '5': '#aa00aa', '6': '#ffaa00', '7': '#aaaaaa',\n" +
        "                '8': '#555555', '9': '#5555ff', 'a': '#55ff55', 'b': '#55ffff',\n" +
        "                'c': '#ff5555', 'd': '#ff55ff', 'e': '#ffff55', 'f': '#ffffff'\n" +
        "            };\n" +
        "            let html = \"\";\n" +
        "            let bold = false;\n" +
        "            let italic = false;\n" +
        "            let color = null;\n" +
        "            \n" +
        "            for (let i = 0; i < text.length; i++) {\n" +
        "                if (text[i] === '§' && i + 1 < text.length) {\n" +
        "                    let code = text[i+1].toLowerCase();\n" +
        "                    i++; \n" +
        "                    if (colorMap[code] !== undefined) {\n" +
        "                        color = colorMap[code];\n" +
        "                    } else if (code === 'l') {\n" +
        "                        bold = true;\n" +
        "                    } else if (code === 'o') {\n" +
        "                        italic = true;\n" +
        "                    } else if (code === 'r') {\n" +
        "                        color = null;\n" +
        "                        bold = false;\n" +
        "                        italic = false;\n" +
        "                    }\n" +
        "                    continue;\n" +
        "                }\n" +
        "                \n" +
        "                let style = \"\";\n" +
        "                if (color) style += `color:${color};`;\n" +
        "                if (bold) style += `font-weight:bold;`;\n" +
        "                if (italic) style += `font-style:italic;`;\n" +
        "                \n" +
        "                let char = text[i];\n" +
        "                if (char === ' ') char = '&nbsp;';\n" +
        "                else if (char === '<') char = '&lt;';\n" +
        "                else if (char === '>') char = '&gt;';\n" +
        "                \n" +
        "                if (style) {\n" +
        "                    html += `<span style=\"${style}\">${char}</span>`;\n" +
        "                } else {\n" +
        "                    html += char;\n" +
        "                }\n" +
        "            }\n" +
        "            return html;\n" +
        "        }\n" +
        "\n" +
        "        function formatText(text) {\n" +
        "            if (text.includes('[img]') && text.includes('[/img]')) {\n" +
        "                const url = text.substring(text.indexOf('[img]') + 5, text.indexOf('[/img]'));\n" +
        "                return `<img src=\"${url}\" class=\"chat-image\" onclick=\"window.open('${url}', '_blank')\" title=\"Нажмите, чтобы открыть\">`;\n" +
        "            }\n" +
        "            return parseMinecraftColors(text);\n" +
        "        }\n" +
        "\n" +
        "        function formatTime(timestamp) {\n" +
        "            const date = new Date(timestamp);\n" +
        "            const h = String(date.getHours()).padStart(2, '0');\n" +
        "            const m = String(date.getMinutes()).padStart(2, '0');\n" +
        "            return `${h}:${m}`;\n" +
        "        }\n" +
        "\n" +
        "        function appendMessageToDOM(sender, text, time, isSelf, isWeb) {\n" +
        "            const msgDiv = document.createElement('div');\n" +
        "            \n" +
        "            if (sender === '[Server]') {\n" +
        "                msgDiv.className = 'msg-row system-msg';\n" +
        "            } else {\n" +
        "                msgDiv.className = `msg-row ${isSelf ? 'self-msg' : ''}`;\n" +
        "            }\n" +
        "\n" +
        "            const timeSpan = document.createElement('span');\n" +
        "            timeSpan.className = 'msg-time';\n" +
        "            timeSpan.textContent = `[${formatTime(time)}]`;\n" +
        "\n" +
        "            const contentSpan = document.createElement('span');\n" +
        "            const formattedSender = parseMinecraftColors(sender);\n" +
        "            const formattedText = formatText(text);\n" +
        "            \n" +
        "            if (sender === '[Server]') {\n" +
        "                contentSpan.innerHTML = formattedText;\n" +
        "            } else if (isWeb) {\n" +
        "                contentSpan.innerHTML = `&lt;<span class=\"sender-name\" style=\"cursor:pointer;\" onclick=\"openPrivateChat('${sender}')\" title=\"Написать личное сообщение\">${formattedSender}</span>&gt; ${formattedText}`;\n" +
        "            } else {\n" +
        "                contentSpan.innerHTML = `&lt;<span class=\"sender-name\" style=\"cursor:default;\">${formattedSender}</span>&gt; ${formattedText}`;\n" +
        "            }\n" +
        "\n" +
        "            msgDiv.appendChild(timeSpan);\n" +
        "            msgDiv.appendChild(contentSpan);\n" +
        "            messagesArea.appendChild(msgDiv);\n" +
        "            messagesArea.scrollTop = messagesArea.scrollHeight;\n" +
        "        }\n" +
        "        \n" +
        "        function openPrivateChat(nick) {\n" +
        "            const currentNick = nickInput.value.trim();\n" +
        "            if (nick === currentNick || nick === '[Server]') return;\n" +
        "            \n" +
        "            let cleanNick = nick.replace(/ \\(Web\\)$/, '');\n" +
        "            if (cleanNick === currentNick) return;\n" +
        "            \n" +
        "            const tabId = 'pm-' + cleanNick;\n" +
        "            let tab = document.querySelector(`.tab[data-target=\"${tabId}\"]`);\n" +
        "            if (!tab) {\n" +
        "                tab = document.createElement('div');\n" +
        "                tab.className = 'tab';\n" +
        "                tab.setAttribute('data-target', tabId);\n" +
        "                tab.innerHTML = `${i18n[currentLang].pmWith}${cleanNick} <span class=\"tab-close\" onclick=\"closeTab(event, '${tabId}')\">&times;</span>`;\n" +
        "                \n" +
        "                tab.addEventListener('click', () => switchTab(tabId));\n" +
        "                tabsBar.appendChild(tab);\n" +
        "            }\n" +
        "            switchTab(tabId);\n" +
        "            sidebar.classList.remove('open');\n" +
        "            chatsSidebar.classList.remove('open');\n" +
        "        }\n" +
        "        \n" +
        "        function closeTab(event, tabId) {\n" +
        "            event.stopPropagation();\n" +
        "            const tab = document.querySelector(`.tab[data-target=\"${tabId}\"]`);\n" +
        "            if (tab) {\n" +
        "                tab.remove();\n" +
        "                if (activeTab === tabId) {\n" +
        "                    switchTab('global');\n" +
        "                }\n" +
        "            }\n" +
        "        }\n" +
        "        \n" +
        "        function switchTab(target) {\n" +
        "            document.querySelectorAll('.tab').forEach(t => {\n" +
        "                if (t.getAttribute('data-target') === target) {\n" +
        "                    t.classList.add('active');\n" +
        "                    t.classList.remove('unread');\n" +
        "                } else {\n" +
        "                    t.classList.remove('active');\n" +
        "                }\n" +
        "            });\n" +
        "            activeTab = target;\n" +
        "            renderMessages();\n" +
        "        }\n" +
        "        \n" +
        "        document.querySelector('.tab[data-target=\"global\"]').addEventListener('click', () => switchTab('global'));\n" +
        "        \n" +
        "        function renderMessages() {\n" +
        "            messagesArea.innerHTML = '';\n" +
        "            const currentNick = nickInput.value.trim();\n" +
        "            if (activeTab === 'global') {\n" +
        "                globalMessages.forEach(msg => {\n" +
        "                    const isSelf = (msg.sender === currentNick);\n" +
        "                    appendMessageToDOM(msg.sender, msg.text, msg.time, isSelf, msg.isWeb);\n" +
        "                });\n" +
        "            } else {\n" +
        "                const other = activeTab.replace('pm-', '');\n" +
        "                const list = pmMessages[other] || [];\n" +
        "                list.forEach(msg => {\n" +
        "                    const isSelf = (msg.from === currentNick);\n" +
        "                    // All PMs are web communication\n" +
        "                    appendMessageToDOM(msg.from, msg.text, msg.time, isSelf, true);\n" +
        "                });\n" +
        "            }\n" +
        "            messagesArea.scrollTop = messagesArea.scrollHeight;\n" +
        "        }\n" +
        "\n" +
        "        function loadServerInfo() {\n" +
        "            fetch('/server-info')\n" +
        "                .then(res => res.json())\n" +
        "                .then(data => {\n" +
        "                    serverName.innerHTML = parseMinecraftColors(data.motd);\n" +
        "                    updateToggleSidebarBtnText(data.online, data.max);\n" +
        "                    if (data.hasOwnProperty('clickerEnabled')) {\n" +
        "                        openClickerBtn.style.display = data.clickerEnabled ? 'block' : 'none';\n" +
        "                    }\n" +
        "                    if (data.hasOwnProperty('allowImageUploads')) {\n" +
        "                        attachBtn.style.display = data.allowImageUploads ? 'block' : 'none';\n" +
        "                    }\n" +
        "                })\n" +
        "                .catch(err => console.error(\"Error loading server info\", err));\n" +
        "            \n" +
        "            srvIcon.src = '/server-icon.png?t=' + Date.now();\n" +
        "            srvIcon.onerror = () => srvIcon.style.display = 'none';\n" +
        "        }\n" +
        "        \n" +
        "        function loadPlayers() {\n" +
        "            fetch('/players')\n" +
        "                .then(res => res.json())\n" +
        "                .then(data => {\n" +
        "                    playerList.innerHTML = '';\n" +
        "                    if (data.length === 0) {\n" +
        "                        const emptyDiv = document.createElement('div');\n" +
        "                        emptyDiv.style.color = '#777';\n" +
        "                        emptyDiv.style.textAlign = 'center';\n" +
        "                        emptyDiv.style.padding = '20px 0';\n" +
        "                        emptyDiv.style.fontSize = '10px';\n" +
        "                        emptyDiv.textContent = i18n[currentLang].noPlayers;\n" +
        "                        playerList.appendChild(emptyDiv);\n" +
        "                        return;\n" +
        "                    }\n" +
        "                    data.forEach(p => {\n" +
        "                        const row = document.createElement('div');\n" +
        "                        if (p.isWeb) {\n" +
        "                            row.className = 'player-row clickable';\n" +
        "                            row.addEventListener('click', () => openPrivateChat(p.name));\n" +
        "                        } else {\n" +
        "                            row.className = 'player-row';\n" +
        "                        }\n" +
        "                        \n" +
        "                        const img = document.createElement('img');\n" +
        "                        img.className = 'player-avatar';\n" +
        "                        if (p.isWeb) {\n" +
        "                            img.src = `/avatar/${p.name}`;\n" +
        "                            img.onerror = function() { this.src = 'data:image/svg+xml;utf8,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22 fill=%22%23888888%22><path d=%22M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z%22/></svg>'; this.onerror=null; };\n" +
        "                        } else {\n" +
        "                            img.src = `https://minotar.net/helm/${p.name}/32`;\n" +
        "                        }\n" +
        "                        img.alt = '';\n" +
        "                        \n" +
        "                        const name = document.createElement('span');\n" +
        "                        name.className = 'player-name';\n" +
        "                        name.textContent = p.name + (p.isWeb ? ' (Web)' : '');\n" +
        "                        \n" +
        "                        row.appendChild(img);\n" +
        "                        row.appendChild(name);\n" +
        "                        playerList.appendChild(row);\n" +
        "                    });\n" +
        "                })\n" +
        "                .catch(err => console.error(\"Error loading players list\", err));\n" +
        "        }\n" +
        "        \n" +
        "        function renderChatsList() {\n" +
        "            chatsList.innerHTML = '';\n" +
        "            const currentNick = nickInput.value.trim();\n" +
        "            const chatPartners = Object.keys(pmMessages);\n" +
        "            \n" +
        "            if (chatPartners.length === 0) {\n" +
        "                const emptyDiv = document.createElement('div');\n" +
        "                emptyDiv.style.color = '#777';\n" +
        "                emptyDiv.style.textAlign = 'center';\n" +
        "                emptyDiv.style.padding = '20px 0';\n" +
        "                emptyDiv.style.fontSize = '9px';\n" +
        "                emptyDiv.textContent = i18n[currentLang].noChats;\n" +
        "                chatsList.appendChild(emptyDiv);\n" +
        "                return;\n" +
        "            }\n" +
        "            \n" +
        "            chatPartners.forEach(partner => {\n" +
        "                const row = document.createElement('div');\n" +
        "                row.className = 'player-row clickable';\n" +
        "                row.addEventListener('click', () => {\n" +
        "                    openPrivateChat(partner);\n" +
        "                });\n" +
        "                \n" +
        "                const img = document.createElement('img');\n" +
        "                img.className = 'player-avatar';\n" +
        "                img.src = `/avatar/${partner}`;\n" +
        "                img.onerror = function() { this.src = `https://minotar.net/helm/${partner}/32`; this.onerror=null; };\n" +
        "                img.alt = '';\n" +
        "                \n" +
        "                const name = document.createElement('span');\n" +
        "                name.className = 'player-name';\n" +
        "                name.textContent = partner;\n" +
        "                \n" +
        "                const tabId = 'pm-' + partner;\n" +
        "                const tab = document.querySelector(`.tab[data-target=\"${tabId}\"]`);\n" +
        "                if (tab && tab.classList.contains('unread')) {\n" +
        "                    name.style.color = '#ff5555';\n" +
        "                    name.textContent += ' (*)';\n" +
        "                }\n" +
        "                \n" +
        "                row.appendChild(img);\n" +
        "                row.appendChild(name);\n" +
        "                chatsList.appendChild(row);\n" +
        "            });\n" +
        "        }\n" +
        "\n" +
        "        function loadHistory() {\n" +
        "            return fetch('/history')\n" +
        "                .then(res => res.json())\n" +
        "                .then(data => {\n" +
        "                    globalMessages = data;\n" +
        "                    if (activeTab === 'global') renderMessages();\n" +
        "                })\n" +
        "                .catch(err => console.error(\"Error loading history:\", err));\n" +
        "        }\n" +
        "        \n" +
        "        function loadPrivateHistory() {\n" +
        "            const nick = nickInput.value.trim();\n" +
        "            if (!nick) return;\n" +
        "            fetch('/private/history?user=' + encodeURIComponent(nick))\n" +
        "                .then(res => res.json())\n" +
        "                .then(data => {\n" +
        "                    pmMessages = {};\n" +
        "                    data.forEach(msg => {\n" +
        "                        const other = (msg.from.toLowerCase() === nick.toLowerCase()) ? msg.to : msg.from;\n" +
        "                        if (!pmMessages[other]) pmMessages[other] = [];\n" +
        "                        pmMessages[other].push(msg);\n" +
        "                    });\n" +
        "                    if (activeTab !== 'global') renderMessages();\n" +
        "                    if (chatsSidebar.classList.contains('open')) renderChatsList();\n" +
        "                })\n" +
        "                .catch(err => console.error(\"Error loading PM history:\", err));\n" +
        "        }\n" +
        "\n" +
        "        let eventSource;\n" +
        "        function connectSSE() {\n" +
        "            if (eventSource) eventSource.close();\n" +
        "            \n" +
        "            statusPanel.className = 'status connecting';\n" +
        "            statusText.textContent = i18n[currentLang].connecting;\n" +
        "            \n" +
        "            const nick = nickInput.value.trim();\n" +
        "            eventSource = new EventSource('/stream?nick=' + encodeURIComponent(nick));\n" +
        "            \n" +
        "            eventSource.onopen = () => {\n" +
        "                statusPanel.className = 'status';\n" +
        "                statusText.textContent = i18n[currentLang].connected;\n" +
        "            };\n" +
        "            \n" +
        "            eventSource.onerror = (e) => {\n" +
        "                statusPanel.className = 'status connecting';\n" +
        "                statusText.textContent = i18n[currentLang].errorStatus;\n" +
        "                eventSource.close();\n" +
        "                setTimeout(connectSSE, 3000);\n" +
        "            };\n" +
        "            \n" +
        "            eventSource.onmessage = (event) => {\n" +
        "                try {\n" +
        "                    const data = JSON.parse(event.data);\n" +
        "                    const currentNick = nickInput.value.trim();\n" +
        "                    \n" +
        "                    if (data.type === 'private') {\n" +
        "                        if (data.from.toLowerCase() === currentNick.toLowerCase() || data.to.toLowerCase() === currentNick.toLowerCase()) {\n" +
        "                            const other = (data.from.toLowerCase() === currentNick.toLowerCase()) ? data.to : data.from;\n" +
        "                            if (!pmMessages[other]) pmMessages[other] = [];\n" +
        "                            pmMessages[other].push(data);\n" +
        "                            \n" +
        "                            const otherTabId = 'pm-' + other;\n" +
        "                            if (activeTab === otherTabId) {\n" +
        "                                renderMessages();\n" +
        "                            } else {\n" +
        "                                let tab = document.querySelector(`.tab[data-target=\"${otherTabId}\"]`);\n" +
        "                                if (!tab) {\n" +
        "                                    tab = document.createElement('div');\n" +
        "                                    tab.className = 'tab unread';\n" +
        "                                    tab.setAttribute('data-target', otherTabId);\n" +
        "                                    tab.innerHTML = `${i18n[currentLang].pmWith}${other} <span class=\"tab-close\" onclick=\"closeTab(event, '${otherTabId}')\">&times;</span>`;\n" +
        "                                    tab.addEventListener('click', () => switchTab(otherTabId));\n" +
        "                                    tabsBar.appendChild(tab);\n" +
        "                                } else {\n" +
        "                                    tab.classList.add('unread');\n" +
        "                                }\n" +
        "                            }\n" +
        "                            \n" +
        "                            if (chatsSidebar.classList.contains('open')) {\n" +
        "                                renderChatsList();\n" +
        "                            }\n" +
        "                        }\n" +
        "                    } else {\n" +
        "                        globalMessages.push(data);\n" +
        "                        if (globalMessages.length > 150) globalMessages.shift();\n" +
        "                        \n" +
        "                        if (activeTab === 'global') {\n" +
        "                            renderMessages();\n" +
        "                        } else {\n" +
        "                            document.querySelector('.tab[data-target=\"global\"]').classList.add('unread');\n" +
        "                        }\n" +
        "                        \n" +
        "                        if (data.sender === '[Server]' && (data.text.includes('joined') || data.text.includes('left'))) {\n" +
        "                            loadServerInfo();\n" +
        "                            loadPlayers();\n" +
        "                        }\n" +
        "                    }\n" +
        "                } catch (e) {\n" +
        "                    console.error(\"Error parsing message\", e);\n" +
        "                }\n" +
        "            };\n" +
        "        }\n" +
        "\n" +
        "        function sendMessage(text) {\n" +
        "            const nick = nickInput.value.trim();\n" +
        "            if (!text || !nick) return;\n" +
        "\n" +
        "            if (activeTab === 'global') {\n" +
        "                const params = new URLSearchParams();\n" +
        "                params.append('nick', nick);\n" +
        "                params.append('message', text);\n" +
        "                fetch('/send', {\n" +
        "                    method: 'POST',\n" +
        "                    headers: {\n" +
        "                        'Content-Type': 'application/x-www-form-urlencoded'\n" +
        "                    },\n" +
        "                    body: params\n" +
        "                }).catch(err => console.error(\"Error sending message\", err));\n" +
        "            } else {\n" +
        "                const other = activeTab.replace('pm-', '');\n" +
        "                const params = new URLSearchParams();\n" +
        "                params.append('from', nick);\n" +
        "                params.append('to', other);\n" +
        "                params.append('message', text);\n" +
        "                fetch('/private/send', {\n" +
        "                    method: 'POST',\n" +
        "                    headers: {\n" +
        "                        'Content-Type': 'application/x-www-form-urlencoded'\n" +
        "                    },\n" +
        "                    body: params\n" +
        "                }).catch(err => console.error(\"Error sending PM\", err));\n" +
        "            }\n" +
        "        }\n" +
        "\n" +
        "        loadServerInfo();\n" +
        "        loadPlayers();\n" +
        "        loadMyAvatar();\n" +
        "        loadClickerStatus();\n" +
        "        loadHistory().then(() => {\n" +
        "            loadPrivateHistory();\n" +
        "            connectSSE();\n" +
        "        });\n" +
        "        \n" +
        "        openClickerBtn.addEventListener('click', () => {\n" +
        "            loadClickerStatus();\n" +
        "            clickerModal.classList.add('open');\n" +
        "        });\n" +
        "        closeClickerBtn.addEventListener('click', () => {\n" +
        "            clickerModal.classList.remove('open');\n" +
        "        });\n" +
        "        clickerBlock.addEventListener('click', clickBlock);\n" +
        "        transferSendBtn.addEventListener('click', transferOre);\n" +
        "        transferMaxBtn.addEventListener('click', () => { if (selectedOreSlot) transferAmountInput.value = clickerInventory[selectedOreSlot] || 1; });\n" +

        "\n" +
        "        setInterval(() => {\n" +
        "            loadServerInfo();\n" +
        "            loadPlayers();\n" +
        "        }, 15000);\n" +
        "\n" +
        "        chatForm.addEventListener('submit', (e) => {\n" +
        "            e.preventDefault();\n" +
        "            const text = msgInput.value.trim();\n" +
        "            if (!text) return;\n" +
        "            msgInput.value = '';\n" +
        "            sendMessage(text);\n" +
        "        });\n" +
        "    </script>\n" +
        "</body>\n" +
        "</html>";

    private static final String INDEX_HTML = INDEX_HTML_PART1 + new String(INDEX_HTML_PART2);
}