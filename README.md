# cupid-safeguard

This project demonstrates a simple HTTPS server application written in C that:
- Accepts local (private/loopback) client connections only.
- Serves an HTML page allowing users to submit data.
- Broadcasts new data to all connected clients in real-time via **Server-Sent Events (SSE)**.
- Uses **OpenSSL** to enable HTTPS/TLS with a self-signed certificate.

> **Note**: This is **not** a production-ready application—it's primarily for demonstration and local testing.

---

## Features

- **Live Updates via SSE**: Any new data submission is instantly pushed to all connected clients.
- **Basic Endpoints**:
  - `GET /`: Serves the main page (HTML + SSE client).
  - `GET /events`: Opens an SSE stream for real-time data updates.
  - `POST /submit`: Submits new data (stored in memory, broadcast to SSE clients).
  - `GET /shutdown`: Gracefully shuts down the server.
- **Local IP Detection**: Dynamically finds a suitable local IP address for binding.
- **Connection Restriction**: Only private or loopback IPv4 clients are accepted (e.g., `127.x.x.x`, `192.168.x.x`, `10.x.x.x`, etc.).
- **Self-Signed Certificate Generation (if missing)**: Automatically generates `server.key` and `server.crt` via `openssl` commands if they're not found.
- **Simple Logging**: Logs submitted data and server events to stdout.

---

## How It Works

1. **Certificate and Key**  
   - On startup, the server checks for `server.crt` and `server.key` in the current directory.
   - If not found, it automatically runs `openssl req` to generate a new self-signed certificate and key (valid for 365 days).
   
2. **SSL Initialization**  
   - Uses `OpenSSL` functions to initialize a new `SSL_CTX` (SSL context).
   - Loads the certificate (`server.crt`) and private key (`server.key`) into the context.

3. **TCP Socket + TLS**  
   - The server determines your local IP address using a `socket` trick to connect to a well-known IP (e.g., `8.8.8.8`) and calls `getsockname()` to retrieve the local address.
   - Binds a socket to that local IP on port **8080**.
   - Listens for inbound connections and **accepts** them only if the client is from a private or loopback network range.
   - For each accepted connection, performs the **TLS handshake**.

4. **Request Handling**  
   - Reads the HTTP request over the encrypted TLS channel.
   - Parses the method (e.g., `GET`, `POST`) and path (e.g., `/`, `/events`, `/submit`, `/shutdown`).
   - Serves the appropriate response:
     - The root HTML page (for `GET /`).
     - The SSE stream (for `GET /events`).
     - Data submission endpoint (for `POST /submit`).
     - Shutdown endpoint (for `GET /shutdown`).
   - SSE clients remain connected for streaming events; newly submitted data is **broadcast** to them in real-time.

---

## Building and Running

1. **Install OpenSSL** (if not already installed).  
   - On Linux (Ubuntu/Debian), for example:  
     ```bash
     sudo apt-get update && sudo apt-get install libssl-dev
     ```
   - On macOS (with Homebrew):  
     ```bash
     brew install openssl
     ```

2. **Compile** the source code.  
   Make sure to link against the SSL and crypto libraries, for example:
   ```bash
   gcc server.c -o server -lssl -lcrypto
   ```
   Adjust the source file name if necessary.

3. **Run** the program:
   ```bash
   ./server
   ```
   - The program will automatically generate `server.crt` and `server.key` if they’re not present.
   - It then prints something like:
     ```
     Local IP determined: 192.168.1.123
     [INFO] HTTPS server listening on https://192.168.1.123:8080/
     ```
   - (The exact IP may vary depending on your network setup.)

4. **In Your Browser**:  
   Visit the URL shown in the console (e.g. `https://192.168.1.123:8080`).  
   - **Note**: You may see a security warning because this is a self-signed certificate. You can proceed by adding a security exception in your browser for local testing.

---

## Usage

1. **Navigate** to `https://<YOUR_LOCAL_IP>:8080/`.
2. You’ll see:
   - A title, "cupid-safeguard"
   - A list of previously submitted data (if any)
   - A form to submit new data
3. **Submit** some data by typing into the form and clicking **Submit**.
4. **Watch**:
   - The server logs the new data in the console.
   - All connected browsers instantly update to show the new data item (thanks to SSE).

---

## Stopping the Server

You have two main options:

- **Ctrl+C** in the terminal where `./server` is running.
- **GET /shutdown**: Navigate to `https://<YOUR_LOCAL_IP>:8080/shutdown` in your browser. The server will log and then gracefully shut down.

---

## Notes & Roadmap

- **Security**:  
  - The server currently restricts connections to private/loopback addresses, but otherwise **does not** implement advanced authentication or authorization.  
  - The self-signed certificate is fine for local testing but not suitable for production.  
  - Consider using a proper CA-signed certificate if you deploy beyond local testing.
- **Input Sanitization**: The user input is minimally sanitized (basic URL decoding). For real-world usage, ensure robust sanitization to avoid injection attacks.
- **Storage**: Submitted data is stored in memory only and is lost on shutdown. Storing data in a persistent database or file is advisable for production.
- **SSE Implementation**:  
  - We store only the client file descriptors in an array. For a robust SSE solution over TLS, you’d store `(fd, SSL*)` pairs, so you can properly handle writes to each client’s SSL connection.
- **Enhancements**: Potential improvements include:
  - Stronger TLS configuration (e.g., forcing modern ciphers).
  - More configurable server options (port, IP restrictions, etc.).
  - Detailed logging or integrating with a structured logging system.
  - Implementing a client “heartbeat” to detect and remove stale SSE connections.
