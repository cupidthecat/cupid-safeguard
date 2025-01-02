# cupid-safeguard

**Ever run into a situation where you've got important data or a code on one device, and you just can't easily get it onto another device without exposing it or jumping through complicated hoops?**  

This project aims to **simplify** that scenario by giving you a small, self-contained HTTPS server. You can run `cupid-safeguard` on a trusted device in your private or home network, then securely submit and view data from other devices on the same network—**without** exposing it to the wider internet or depending on public cloud services.

It demonstrates a simple server application written in C that:
- Accepts **private or loopback** (127.x.x.x, 192.168.x.x, 10.x.x.x, 172.16-31.x.x) client connections only.
- Serves a basic HTML page allowing users to submit data.
- Broadcasts new data to all connected clients in real-time via **Server-Sent Events (SSE)**.
- Uses **OpenSSL** to enable HTTPS/TLS with a self-signed certificate (generated automatically if missing).

> **Note**: This is **not** a production-ready application—it's primarily for demonstration and local testing.

---

## Features

1. **Live Updates (SSE)**  
   Any new data submission is instantly pushed to all connected browsers/tabs via Server-Sent Events.

2. **Endpoints**  
   - **GET /**  
     Serves the main HTML page, which also connects to the SSE endpoint (`/events`) for live updates.
   - **GET /events**  
     Opens a persistent SSE stream for real-time data updates.
   - **POST /submit**  
     Submits new data (stored in-memory) and broadcasts to all SSE clients.
   - **GET /shutdown**  
     Gracefully shuts down the server.

3. **Local IP Detection**  
   Dynamically finds a suitable local IP address by performing a UDP “connect” to `8.8.8.8` on port 53, then calling `getsockname()`—so you don’t have to hardcode your local IP address.

4. **Connection Restriction**  
   Only private or loopback IPv4 addresses are accepted, providing a simple safeguard against external connections. (This is not a perfect security measure, but it significantly reduces casual external access.)

5. **Self-Signed Certificate Generation**  
   If `server.crt` or `server.key` are missing, `cupid-safeguard` automatically runs `openssl` commands to generate a new 2048-bit RSA key and self-signed certificate (valid for 365 days).

6. **Simple Logging**  
   Logs submitted data and server events to `stdout` for quick diagnostics.

---

## How It Works

1. **Certificate and Key Check**  
   - On startup, `cupid-safeguard` checks if `server.crt` and `server.key` exist.
   - If missing, it automatically runs:
     ```bash
     openssl req -x509 -newkey rsa:2048 -nodes \
       -keyout server.key -out server.crt -days 365 \
       -subj "/CN=localhost"
     ```
   - This generates a new self-signed certificate (`server.crt`) and private key (`server.key`) in the current directory.

2. **SSL Initialization**  
   - Uses OpenSSL to create a new SSL context (`SSL_CTX*`).
   - Loads your certificate and key into the context.
   - Enforces TLS 1.2 or higher and a modern cipher suite.

3. **Socket Setup**  
   - Determines your local IP using a UDP “connect” trick.
   - Binds to `0.0.0.0:<PORT>` or the discovered local IP on port **8080** by default, then starts listening for inbound connections.

4. **Restrict Inbound Connections**  
   - On `accept()`, checks the client’s IPv4 address to see if it falls within a private/loopback range.  
   - If not, it immediately closes the connection.

5. **TLS Handshake & HTTP Parsing**  
   - For each accepted connection, performs a TLS handshake (`SSL_accept`).  
   - Reads the HTTP request via `SSL_read`.
   - Parses the method (GET/POST) and path (/, /events, /submit, /shutdown).

6. **Response & SSE**  
   - For a **GET /** request, sends the main HTML page over SSL.  
   - For **GET /events**, sends HTTP headers for `text/event-stream` and keeps the connection open, storing the client fd (and ideally an SSL pointer in a real production scenario) to push SSE updates.  
   - For **POST /submit**, appends the posted data to an in-memory list and broadcasts an SSE `newEntry` event to all connected SSE clients.  
   - For **GET /shutdown**, replies with a simple message and sets a flag that stops the server loop, shutting down gracefully.

---

## Building and Running

1. **Install OpenSSL** (if not already available):
   - **Ubuntu/Debian**:
     ```bash
     sudo apt-get update
     sudo apt-get install libssl-dev
     ```
   - **macOS (Homebrew)**:
     ```bash
     brew install openssl
     ```
   - **Windows**:  
     Can install OpenSSL binaries from [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html) or similar.

2. **Compile the Server**  
   Make sure to link against the SSL and crypto libraries. For example, on Linux:
   ```bash
   gcc server.c -o cupid-safeguard -lssl -lcrypto
   ```
   (Adjust the source file name if yours differs.)

3. **Run the Binary**  
   ```bash
   ./cupid-safeguard
   ```
   - By default, it listens on **port 8080**.
   - If `server.crt` or `server.key` are missing, they’ll be automatically generated.
   - You’ll see something like:
     ```
     [INFO] Generating self-signed certificate and private key...
     [INFO] Self-signed certificate generated.
     Local IP determined: 192.168.1.123
     [INFO] HTTPS server listening on https://192.168.1.123:8080/
     ```

4. **Open in Browser**  
   Navigate to `https://<YOUR_LOCAL_IP>:8080` in your browser.  
   - Expect a **security warning** about the self-signed certificate. Accept/continue for local testing.

---

## Usage

1. **Visit the Main Page**  
   You’ll see:
   - A heading: *cupid-safeguard (HTTPS/TLS)*
   - A list of any previously submitted data
   - A text field to submit new data

2. **Submit Data**  
   - Type something in the form and click **Submit**.
   - The server logs the submission to stdout.
   - All open browser sessions connected to `/events` instantly update with the new entry (thanks to SSE).

---

## Stopping the Server

- **Ctrl+C** in the terminal running `./cupid-safeguard`.
- Alternatively, navigate to `https://<YOUR_LOCAL_IP>:8080/shutdown` in your browser to invoke a graceful shutdown.

---

## Notes & Roadmap

1. **Security**  
   - Currently restricted to private/loopback IP addresses. This is simple but not foolproof for all network topologies.  
   - Uses a **self-signed** certificate by default. For a real deployment, consider a legitimate cert (e.g., via Let’s Encrypt), and additional access controls.

2. **Input Sanitization**  
   - Minimal URL decoding is done. For production, stronger sanitization (e.g., HTML escaping) is recommended.

3. **In-Memory Storage**  
   - Data is only stored in a fixed-size memory array. Once the server stops, submissions are lost. Consider writing to a file or database if persistence is required.

4. **SSE Implementation**  
   - This sample code only stores raw client file descriptors for SSE. A robust approach for TLS would maintain `(SSL*, fd)` pairs so that SSE broadcasts go through `SSL_write`.

5. **Possible Enhancements**  
   - More configuration options (port, interface, IP restriction, max client connections).  
   - Session-based authentication or IP whitelisting for additional security.  
   - Automatic detection and removal of stale SSE connections (heartbeats).  
   - Logging improvements (timestamps, log levels).
