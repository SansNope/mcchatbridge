# McChatBridge

A NeoForge Minecraft server mod that creates a secure, pixel-themed local web interface to interact with in-game chat, direct messages, and includes a built-in Clicker mini-game.

## Features
* **In-Game Chat Mirroring:** Real-time synchronization between Minecraft server chat and the web interface using Server-Sent Events (SSE).
* **Direct Private Messages (PM):** Web players can send private messages to other web players.
* **AES-256-GCM PM Encryption:** Private messages history (`mcchatbridge_private.txt`) is fully encrypted using the AES-256-GCM cipher. A unique key is generated once in `mcchatbridge_key.bin` and kept secure on the server.
* **Custom Avatar System:** Users can upload custom PNG/JPEG/GIF avatars dynamically.
* **Clicker Mini-Game:** A built-in pixelated mining game where you mine blocks, gather resources, and transfer them directly to players on the server.
* **Multi-Language Web UI:** Instant language switching between English (default) and Russian directly on the web page.

## File Structure
* `config/mcchatbridge.json` - Global mod configuration file (auto-generated, manually tunable). Allows configuring:
  * Port (Default: `8080`)
  * Features toggle (Clicker, Image uploads, etc.)
* `mcchatbridge_key.bin` - 256-bit AES encryption key. **Do not share this file!**
* `mcchatbridge_private.txt` - Encrypted private messages history.
* `uploads/` - Custom uploaded avatars and images.

## Compilation and Build
This project can be compiled and packed using the provided `compile_mod.py` helper script:
```bash
python compile_mod.py
```
This will compile the Java source files and create a ready-to-use NeoForge JAR mod inside `mods/` directory.

## Installation
1. Put the compiled `.jar` file into the server's `mods` folder.
2. Start the server once to generate configuration files.
3. Access the web interface in your browser at `http://<your-server-ip>:<configured-port>/`.
