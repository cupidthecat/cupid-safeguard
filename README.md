# cupid-safeguard

This is a simple server application written in C that demonstrates how to:
- Accept local (private/loopback) client connections.
- Serve an HTML page that allows users to submit data.
- Broadcast the data to all connected clients in real-time via **Server-Sent Events (SSE)**.

It restricts connections to private/loopback IPv4 addresses for basic security. However, please note that this is **not** a production-ready application—it's primarily for demonstration and local testing.

---

## Features

- **Live Updates**: Using SSE, any new data submissions are instantly broadcast to all connected clients.
- **Basic Request Handling**: Supports:
  - `GET /` - Serves the main page.
  - `GET /events` - Opens an SSE stream to receive real-time updates.
  - `POST /submit` - Submits data (stored in memory and broadcast to connected SSE clients).
  - `GET /shutdown` - Gracefully shuts down the server.
- **Local IP Detection**: Dynamically determines the local IP address to bind to.
- **Simple Logging**: Prints logs for submitted data and server actions.

---

## How It Works

1. The program starts by finding your local IP address (using a `socket` trick with DNS).
2. It then binds to port **8080** (by default) on your local IP address and starts listening for connections.
3. Only clients connecting via private or loopback addresses (e.g., `127.x.x.x`, `192.168.x.x`, etc.) will be served.
4. When a client accesses the root (`/`), the server responds with an HTML page containing:
   - A list of previously submitted data items.
   - A form to submit new data without reloading the entire page.
   - A JavaScript snippet that establishes a connection to `GET /events` for real-time updates via SSE.
5. When the form is submitted (`POST /submit`), the data is added to the in-memory list and an SSE event is broadcast to all clients, updating their lists in real-time.

---

## Building and Running

1. **Clone or copy** this repository/code onto your local machine.
2. **Compile** the source:
   ```bash
   gcc server.c -o server
   ```
   (Adjust the source file name as needed.)
3. **Run** the compiled program:
   ```bash
   ./server
   ```
4. You should see output indicating that the server is listening on `http://<YOUR_LOCAL_IP>:8080/`.

**Important**: Because the server only accepts requests from private addresses, ensure your client is also on the same local/private network or on `localhost` (127.0.0.1).

---

## Usage

1. Open a web browser and navigate to `http://<YOUR_LOCAL_IP>:8080/`.
2. You should see:
   - A title, "cupid-safeguard"
   - A list (initially empty or showing existing data)
   - An input form
3. Enter data in the form and click **Submit**.
4. Observe:
   - The server logs the new data in the console.
   - The new data item appears immediately for **all** currently connected clients, thanks to SSE.

---

## Stopping the Server

You have two options:

- **Option 1**: Press **Ctrl+C** in the terminal window running the server.
- **Option 2**: Send a request to `http://<YOUR_LOCAL_IP>:8080/shutdown`. This triggers a graceful shutdown.

---

## TODO

- **Enhance Security**  
  - **HTTPS/TLS**: Implement secure connections (TLS/SSL) to protect data in transit.
  - **Authentication/Authorization**: Add user authentication flow, so only authorized users can submit or view data.
  - **Input Sanitization**: Improve sanitizing user input to avoid potential injection attacks.
  - **Rate Limiting**: Limit the number of requests from a single client to prevent abuse.
  - **Configurable IP Restrictions**: Instead of hardcoding, allow custom IP whitelisting or blacklisting via configuration.
- **Robust Logging**: Use a structured logging framework.
- **Persistent Storage**: Optionally store submitted data in a file or database.
- **Graceful Shutdown Enhancements**: Notify connected clients about shutdown events.
