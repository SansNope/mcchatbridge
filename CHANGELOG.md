# Changelog

## v1.0.2

### Added
- **Account system**: login and registration screens are now required before accessing the chat.
- **Sessions**: login is remembered for 7 days via an `HttpOnly` cookie and survives a server restart — no need to log in again.
- **Log out button** in the players panel.
- **Brute-force protection**: rate limiting on login (5 failed attempts per IP, then a 15-minute lockout).
- **Emoji sending**: the emoji picker now works (the button previously did nothing).
- **Image & GIF sending** via the 📎 button (previously non-functional); rendered in-game through ChatImage.
- **Notification sound** (harp) on new messages in both global chat and DMs. The sound is embedded in the mod.
- **Custom panorama (background)**: a personal 🖼️ button (PC only); the background is stored locally in the user's browser.
- **Scroll-to-bottom button**: appears when scrolling up through history, jumps back to the latest messages, is 50% transparent, and blinks yellow on a new message. Square, Minecraft-styled.
- **New endpoints**: `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`, `/notify.wav`.

### Changed
- **Nickname is now bound to the account** and can no longer be edited freely (prevents impersonation).
- **Smelting window fully localized** (EN/RU) — some labels used to always show in Russian.
- **UI language now applies on page load**, not only after switching it manually.
- **Avatar serving** now detects the real file type (PNG/JPEG/GIF) and returns the correct Content-Type.

### Fixed
- **Critical JS error** (`Identifier 'activeClickerTab' has already been declared`) that broke the entire web interface.
- **SSE connection drops**: constant reconnects and `ERR_INCOMPLETE_CHUNKED_ENCODING` errors — the connection now stays open until the client disconnects.
- **Items visually disappearing from the furnace slots** during smelting (a server-side race condition; furnace access is now synchronized).
- **"sent you Air!" message** when transferring items to a player — the item name is now read before it is added to the inventory.
- **Hardcoded Russian labels** that appeared in English mode (chat/furnace tabs, tooltips).

### Security
- **Password hashing**: PBKDF2-HMAC-SHA256 (210,000 iterations) with a per-user salt. Passwords are never stored in plain text.
- **Identity binding to the session**: sending messages, sending DMs, reading DM history, and uploading an avatar all use the nickname from the session — you cannot post as someone else or read other people's DMs.
- **Avatar upload validation**: real file-type check via magic bytes, plus a 2 MB size limit.
- **Fixed a path-traversal vulnerability** in avatar nickname handling.

### Notes
- New files created automatically at runtime: `config/mcchatbridge_accounts.json` (salt + hash) and `config/mcchatbridge_sessions.json`.
- The mod runs over plain HTTP. For an untrusted network, putting it behind an HTTPS reverse proxy is recommended (and the session cookie can then use the `Secure` flag).
