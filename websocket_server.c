/*
 * Minimal WebSocket Server Implementation for macOS
 *
 * This example implements a basic WebSocket server that:
 *   - Listens on port 8080.
 *   - Receives an HTTP Upgrade request from a WebSocket client.
 *   - Parses the "Sec-WebSocket-Key" header.
 *   - Computes the Sec-WebSocket-Accept response key using SHA‑1 and Base64.
 *   - Sends back a proper HTTP/1.1 101 Switching Protocols handshake.
 *   - Receives simple text frames from the client, prints them, and echoes them back.
 *
 * Limitations:
 *   - Only text frames (opcode 0x1) and connection close (opcode 0x8) are handled.
 *   - Only payloads of size ≤ 125 bytes are echoed back.
 *   - No handling for fragmented frames or binary frames.
 *
 * Compile with: clang -o websocket_server websocket_server.c -framework CoreFoundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <CommonCrypto/CommonDigest.h>

#define PORT 8080
#define BUFFER_SIZE 4096

// --- Base64 Encoding ---------------------------------------------------------

/*
 * A simple Base64 encoding function.
 * This implementation computes the output length as 4 * ((len + 2) / 3)
 * and pads with '=' characters if necessary.
 */
char *base64_encode(const unsigned char *src, size_t len) {
    const char *base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = src[i++];
        uint32_t octet_b = i < len ? src[i++] : 0;
        uint32_t octet_c = i < len ? src[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | (octet_c);

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = base64_chars[(triple >> 6)  & 0x3F];
        out[j++] = base64_chars[triple & 0x3F];
    }

    // Add padding if needed
    int mod = len % 3;
    if (mod) {
        out[out_len - 1] = '=';
        if (mod == 1) {
            out[out_len - 2] = '=';
        }
    }
    out[out_len] = '\0';
    return out;
}

// --- Compute the Sec-WebSocket-Accept Key ------------------------------------

/*
 * The WebSocket protocol (RFC 6455) requires that the server take the
 * client's Sec-WebSocket-Key, append a specific “magic string” to it,
 * compute the SHA‑1 hash of the result, and then return the Base64 encoding
 * of that hash as the Sec-WebSocket-Accept header.
 */
char *compute_accept_key(const char *client_key) {
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char concatenated[256];
    snprintf(concatenated, sizeof(concatenated), "%s%s", client_key, magic);

    unsigned char hash[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(concatenated, (CC_LONG)strlen(concatenated), hash);

    char *accept_key = base64_encode(hash, CC_SHA1_DIGEST_LENGTH);
    return accept_key;
}

// --- Helper: Receive Exact Number of Bytes ----------------------------------

/*
 * recv_exact() reads exactly len bytes from the socket.
 * It returns the number of bytes received or a non-positive value on error.
 */
ssize_t recv_exact(int sockfd, void *buf, size_t len) {
    size_t received = 0;
    ssize_t n;
    char *ptr = (char*)buf;
    while (received < len) {
        n = recv(sockfd, ptr + received, len - received, 0);
        if (n <= 0) {
            return n;
        }
        received += n;
    }
    return received;
}

// --- Main: Server Setup, Handshake, and Frame Processing --------------------

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Create the listening socket.
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Allow immediate reuse of the port.
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces.
    address.sin_port = htons(PORT);
    
    // Bind the socket to the port.
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for incoming connections.
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("WebSocket server listening on port %d...\n", PORT);
    
    // Accept a single connection.
    if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    
    // --- Handshake Phase ---
    
    // Read the HTTP Upgrade request.
    char buffer[BUFFER_SIZE];
    int valread = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (valread <= 0) {
        perror("recv");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    buffer[valread] = '\0';
    
    printf("Received handshake request:\n%s\n", buffer);
    
    // Extract the "Sec-WebSocket-Key" header value.
    char *key_header = strstr(buffer, "Sec-WebSocket-Key:");
    if (!key_header) {
        fprintf(stderr, "No Sec-WebSocket-Key header found.\n");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // Advance the pointer past the header name.
    key_header += strlen("Sec-WebSocket-Key:");
    while (*key_header == ' ') key_header++;  // Skip any spaces.
    
    // The key ends at the next CR or LF.
    char *key_end = strpbrk(key_header, "\r\n");
    if (!key_end) {
        fprintf(stderr, "Malformed Sec-WebSocket-Key header.\n");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    size_t key_length = key_end - key_header;
    char client_key[256];
    if (key_length >= sizeof(client_key))
        key_length = sizeof(client_key) - 1;
    strncpy(client_key, key_header, key_length);
    client_key[key_length] = '\0';
    
    printf("Client Key: %s\n", client_key);
    
    // Compute the Sec-WebSocket-Accept key.
    char *accept_key = compute_accept_key(client_key);
    if (!accept_key) {
        fprintf(stderr, "Failed to compute Sec-WebSocket-Accept key.\n");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // Build the handshake response.
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             accept_key);
    
    // Send the handshake response.
    send(client_fd, response, strlen(response), 0);
    printf("Sent handshake response:\n%s\n", response);
    
    free(accept_key);
    
    // --- WebSocket Frame Handling Loop ---
    
    while (1) {
        unsigned char header[2];
        int ret = recv_exact(client_fd, header, 2);
        if (ret <= 0) break;  // Connection closed or error.
        
        // Parse the fixed header.
        unsigned char fin    = header[0] & 0x80;  // FIN flag.
        unsigned char opcode = header[0] & 0x0F;  // Opcode (0x1 = text, 0x8 = close, etc.)
        unsigned char mask   = header[1] & 0x80;  // Mask flag (client frames are masked).
        unsigned long payload_len = header[1] & 0x7F;
        
        // Handle extended payload lengths if needed.
        if (payload_len == 126) {
            unsigned char extended[2];
            ret = recv_exact(client_fd, extended, 2);
            if (ret <= 0) break;
            payload_len = (extended[0] << 8) | extended[1];
        } else if (payload_len == 127) {
            unsigned char extended[8];
            ret = recv_exact(client_fd, extended, 8);
            if (ret <= 0) break;
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | extended[i];
            }
        }
        
        unsigned char masking_key[4];
        if (mask) {
            ret = recv_exact(client_fd, masking_key, 4);
            if (ret <= 0) break;
        }
        
        // Allocate space for the payload data.
        unsigned char *payload_data = malloc(payload_len + 1);
        if (!payload_data) {
            fprintf(stderr, "Memory allocation failed\n");
            break;
        }
        ret = recv_exact(client_fd, payload_data, payload_len);
        if (ret <= 0) {
            free(payload_data);
            break;
        }
        payload_data[payload_len] = '\0'; // Null-terminate (assumes text).
        
        // Unmask the payload if needed.
        if (mask) {
            for (unsigned long i = 0; i < payload_len; i++) {
                payload_data[i] ^= masking_key[i % 4];
            }
        }
        
        // Process based on the opcode.
        if (opcode == 0x1) { // Text frame
            printf("Received message: %s\n", payload_data);
            
            // Echo the message back. Build a simple unmasked text frame.
            // For simplicity, we assume payload_len <= 125.
            size_t response_size = 2 + payload_len;
            unsigned char *ws_response = malloc(response_size);
            if (!ws_response) {
                free(payload_data);
                break;
            }
            ws_response[0] = 0x81; // FIN set and opcode 0x1 (text frame)
            ws_response[1] = payload_len; // No mask, payload length in one byte.
            memcpy(ws_response + 2, payload_data, payload_len);
            send(client_fd, ws_response, response_size, 0);
            free(ws_response);
        } else if (opcode == 0x8) { // Connection close
            printf("Received close frame\n");
            free(payload_data);
            break;
        }
        
        free(payload_data);
    }
    
    // Clean up.
    close(client_fd);
    close(server_fd);
    printf("Connection closed.\n");
    return 0;
}
