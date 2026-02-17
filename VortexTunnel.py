#!/usr/bin/env python3
import sys
import socket
import threading
import logging
import argparse
import ssl

import random
import dns.resolver  # pip install dnspython
from typing import Optional, Callable

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("proxy.log", mode="a")
    ],
)
logger = logging.getLogger("TCPProxy")

# List of User-Agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.121 Safari/537.36"
]
EXTRA_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}


def modify_headers(data: bytes, rotate_ua: bool) -> bytes:
    """Modify HTTP headers to mimic a real browser, optionally rotating the User-Agent."""
    try:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return data
        header = data[:header_end]
        body = data[header_end+4:]
        lines = header.split(b"\r\n")
        new_lines = []
        has_user_agent = False
        for line in lines:
            if line.lower().startswith(b"user-agent:"):
                has_user_agent = True
                if rotate_ua:
                    ua = random.choice(USER_AGENTS).encode()
                    new_lines.append(b"User-Agent: " + ua)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        if not has_user_agent:
            ua = random.choice(USER_AGENTS).encode() if rotate_ua else USER_AGENTS[0].encode()
            new_lines.append(b"User-Agent: " + ua)
        # Append extra headers
        for k, v in EXTRA_HEADERS.items():
            new_lines.append(f"{k}: {v}".encode())
        new_header = b"\r\n".join(new_lines) + b"\r\n\r\n"
        return new_header + body
    except Exception as e:
        logger.error(f"Header modification error: {e}")
        return data


def secure_dns_lookup(domain: str) -> str:
    """Resolve a domain using Cloudflare's DNS (DoH) via dnspython."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1"]
        answer = resolver.resolve(domain)
        return answer[0].to_text()
    except Exception as e:
        logger.error(f"DoH lookup error for {domain}: {e}")
        return domain


class TCPProxy:
    """Production-grade TCP Proxy with advanced browser-mimicking features"""

    def __init__(
        self,
        local_host: str,
        local_port: int,
        remote_host: str,
        remote_port: int,
        ssl_enabled: bool = False,
        ssl_skip_verify: bool = False,
        timeout: int = 30,
        backlog: int = 10,
        request_handler: Optional[Callable[[bytes], bytes]] = None,
        response_handler: Optional[Callable[[bytes], bytes]] = None,
        save_log: Optional[str] = None,
        rotate_ua: bool = False,
        use_doh: bool = False,
        use_ws: bool = False,  # Placeholder for WebSockets tunneling
    ):
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.ssl_enabled = ssl_enabled
        self.ssl_skip_verify = ssl_skip_verify
        self.timeout = timeout
        self.backlog = backlog
        self.request_handler = request_handler or (lambda x: x)
        self.response_handler = response_handler or (lambda x: x)
        self.running = True
        self.save_log = save_log
        self.rotate_ua = rotate_ua
        self.use_doh = use_doh
        self.use_ws = use_ws

    def get_tls_context(self) -> ssl.SSLContext:
        """Create and configure a TLS context to mimic a modern browser (e.g., Chrome)."""
        context = ssl.create_default_context()
        if self.ssl_skip_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        # Set cipher suites similar to Chrome's
        try:
            context.set_ciphers(
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305"
            )
        except Exception as e:
            logger.error(f"Error setting ciphers: {e}")
        return context

    def start(self):
        """Start the proxy server with proper resource management."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.local_host, self.local_port))
            server.listen(self.backlog)
            logger.info(
                f"Proxy started on {self.local_host}:{self.local_port} -> "
                f"{self.remote_host}:{self.remote_port}"
            )
            while self.running:
                try:
                    client_socket, client_addr = server.accept()
                    logger.info(f"New connection from {client_addr[0]}:{client_addr[1]}")
                    threading.Thread(
                        target=self.handle_connection,
                        args=(client_socket,),
                        daemon=True
                    ).start()
                except (KeyboardInterrupt, SystemExit):
                    self.running = False
                    logger.info("Shutting down proxy server...")
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
        finally:
            server.close()
            logger.info("Proxy server stopped.")

    def handle_connection(self, client_socket: socket.socket):
        """Handle incoming connection with proper error handling."""
        try:
            data = client_socket.recv(4096, socket.MSG_PEEK)
            if not data:
                return
            if data.startswith(b'CONNECT'):
                self.handle_https_tunnel(client_socket)
            else:
                self.handle_http_proxy(client_socket, data)
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def handle_https_tunnel(self, client_socket: socket.socket):
        """Handle HTTPS CONNECT requests properly."""
        remote_socket = None
        try:
            data = client_socket.recv(4096)
            host_port = data.decode().split()[1]
            target_host, target_port = host_port.split(":", 1)
            target_port = int(target_port)
            if self.use_doh:
                target_host = secure_dns_lookup(target_host)
            logger.info(f"Establishing HTTPS tunnel to {target_host}:{target_port}")
            remote_socket = socket.create_connection((target_host, target_port), timeout=self.timeout)
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if target_port == 443:
                context = self.get_tls_context()
                remote_socket = context.wrap_socket(remote_socket, server_hostname=target_host)
            self.forward_traffic(client_socket, remote_socket)
        except Exception as e:
            logger.error(f"HTTPS tunnel error: {e}")
        finally:
            if remote_socket:
                try:
                    remote_socket.close()
                except Exception:
                    pass

    def handle_http_proxy(self, client_socket: socket.socket, initial_data: bytes):
        """Handle regular HTTP proxying."""
        remote_socket = None
        try:
            remote_host = self.remote_host
            if self.use_doh:
                remote_host = secure_dns_lookup(self.remote_host)
            remote_socket = socket.create_connection((remote_host, self.remote_port), timeout=self.timeout)
            if self.ssl_enabled:
                context = self.get_tls_context()
                remote_socket = context.wrap_socket(remote_socket, server_hostname=self.remote_host)
            # Modify headers to mimic a browser if rotate_ua is enabled.
            modified_data = modify_headers(initial_data, self.rotate_ua)
            remote_socket.sendall(modified_data)
            self.forward_traffic(client_socket, remote_socket)
        except Exception as e:
            logger.error(f"HTTP proxy error: {e}")
        finally:
            if remote_socket:
                try:
                    remote_socket.close()
                except Exception:
                    pass

    def log_traffic(self, direction: str, data: bytes):
        try:
            with open(self.save_log, "a") as log_file:
                log_file.write(f"\n[{direction}] {len(data)} bytes\n")
                log_file.write(data.decode(errors="replace") + "\n")
                log_file.write("=" * 80 + "\n")
        except Exception as e:
            logger.error(f"Failed to save traffic log: {e}")

    def forward_traffic(self, client_sock: socket.socket, remote_sock: socket.socket):
        """Reliable data forwarding with select, logging, and header processing."""
        sockets = [client_sock, remote_sock]
        while True:
            try:
                rlist, _, xlist = select.select(sockets, [], sockets, self.timeout)
                if xlist:
                    break
                if not rlist:
                    continue
                for sock in rlist:
                    data = sock.recv(4096)
                    if not data:
                        return
                    if sock is client_sock:
                        dest = remote_sock
                        processed = self.request_handler(data)
                        direction = "-> REQUEST"
                    else:
                        dest = client_sock
                        processed = self.response_handler(data)
                        direction = "<- RESPONSE"
                    if self.save_log:
                        self.log_traffic(direction, data)
                    try:
                        dest.sendall(processed)
                    except (BrokenPipeError, ConnectionResetError):
                        return
                    logger.debug(f"Forwarded {len(data)} bytes")
                    self.hexdump(data, direction)
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                break
            except Exception as e:
                logger.error(f"Forwarding error: {e}")
                break

    @staticmethod
    def hexdump(data: bytes, direction: str):
        """Advanced hexdump implementation with concise output."""
        hex_str = ' '.join(f"{b:02x}" for b in data)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        logger.debug(f"{direction} HEX: {hex_str[:64]}{'...' if len(hex_str) > 64 else ''}")
        logger.debug(f"{direction} ASCII: {ascii_str[:32]}{'...' if len(ascii_str) > 32 else ''}")


def parse_args():
    """Improved argument parsing with advanced feature flags."""
    parser = argparse.ArgumentParser(description="Production TCP/HTTP Proxy with advanced browser-mimicking features")
    parser.add_argument("local_host", help="Local listening host")
    parser.add_argument("local_port", type=int, help="Local listening port")
    parser.add_argument("remote_host", help="Remote target host")
    parser.add_argument("remote_port", type=int, help="Remote target port")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL for remote connection")
    parser.add_argument("-i", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-s", "--save-log", help="File to save intercepted traffic", type=str, default=None)
    parser.add_argument("-r","--rotate-ua", action="store_true", help="Enable rotating User-Agent header")
    parser.add_argument("-d", "--doh", action="store_true", help="Use DNS over HTTPS for resolution")
    parser.add_argument("-w", "--ws", action="store_true", help="Use WebSockets for tunneling (placeholder)")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    proxy = TCPProxy(
        local_host=args.local_host,
        local_port=args.local_port,
        remote_host=args.remote_host,
        remote_port=args.remote_port,
        ssl_enabled=args.ssl,
        ssl_skip_verify=args.insecure,
        save_log=args.save_log,
        rotate_ua=args.rotate_ua,
        use_doh=args.doh,
        use_ws=args.ws,
    )
    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("Proxy stopped by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
