#!/usr/bin/env python3
import sys
import socket
import threading
import logging
import argparse
import ssl
import select
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


class TCPProxy:
    """Production-grade TCP Proxy with proper browser support"""

    def __init__(
            self,
            local_host: str,
            local_port: int,
            remote_host: str,
            remote_port: int,
            ssl_enabled: bool = False,
            ssl_skip_verify: bool = False,
            timeout: int = 30,  # Increased timeout for browser operations
            backlog: int = 10,
            request_handler: Optional[Callable[[bytes], bytes]] = None,
            response_handler: Optional[Callable[[bytes], bytes]] = None,
            save_log: Optional[str] = None,
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

    def start(self):
        """Start the proxy server with proper resource management"""
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
        """Handle connection with proper error handling"""
        try:
            # Peek at the first bytes to detect HTTPS CONNECT
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
        """Handle HTTPS CONNECT requests properly"""
        remote_socket = None
        try:
            data = client_socket.recv(4096)
            host_port = data.decode().split()[1]
            target_host, target_port = host_port.split(':', 1)
            target_port = int(target_port)

            logger.info(f"Establishing HTTPS tunnel to {target_host}:{target_port}")

            # Connect to target
            remote_socket = socket.create_connection(
                (target_host, target_port),
                timeout=self.timeout
            )

            # Complete CONNECT handshake
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Enable SSL if needed
            if target_port == 443:
                context = ssl.create_default_context()
                if self.ssl_skip_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                remote_socket = context.wrap_socket(
                    remote_socket,
                    server_hostname=target_host
                )

            # Bidirectional forwarding
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
        """Handle regular HTTP proxying"""
        try:
            remote_socket = socket.create_connection(
                (self.remote_host, self.remote_port),
                timeout=self.timeout
            )

            if self.ssl_enabled:
                context = ssl.create_default_context()
                if self.ssl_skip_verify:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                remote_socket = context.wrap_socket(
                    remote_socket,
                    server_hostname=self.remote_host
                )

            # Send initial data
            remote_socket.sendall(initial_data)
            self.forward_traffic(client_socket, remote_socket)

        except Exception as e:
            logger.error(f"HTTP proxy error: {e}")
        finally:
            try:
                remote_socket.close()
            except Exception:
                pass

    def log_traffic(self, direction: str, data: bytes):
        try:
            with open(self.save_log, "a") as log_file:
                log_file.write(f"\n[{direction}] {len(data)} bytes\n")
                log_file.write(data.decode(errors="replace") + "\n")
                log_file.write("=" * 80 * "\n")
        except Exception as e:
            logger.error(f"Failed to save traffic log: {e}")


    def forward_traffic(self, client_sock: socket.socket, remote_sock: socket.socket):
        """Reliable data forwarding with select"""
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
                        direction = "<- REQUEST"

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
        """Clean hexdump implementation"""
        hex_str = ' '.join(f"{b:02x}" for b in data)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        logger.debug(f"{direction} HEX: {hex_str[:64]}{'...' if len(hex_str) > 64 else ''}")
        logger.debug(f"{direction} ASCII: {ascii_str[:32]}{'...' if len(ascii_str) > 32 else ''}")


def parse_args():
    """Improved argument parsing"""
    parser = argparse.ArgumentParser(description="Production TCP/HTTP Proxy")
    parser.add_argument("local_host", help="Local listening host")
    parser.add_argument("local_port", type=int, help="Local listening port")
    parser.add_argument("remote_host", help="Remote target host")
    parser.add_argument("remote_port", type=int, help="Remote target port")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL for remote connection")
    parser.add_argument("-i", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("-s", "--save-log",help="File to save intercepted traffic", type=str,default=None)
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
    )

    try:
        proxy.start()
    except KeyboardInterrupt:
        logger.info("Proxy stopped by user")
        sys.exit(0)


if __name__ == "__main__":
    main()