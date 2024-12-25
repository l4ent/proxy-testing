import socks
import socket
import ssl
import time
import statistics
from urllib.parse import urlparse

# Number of requests to perform
NUM_REQUESTS = 10

# Function to measure timing metrics
def measure_request(proxy_url, target_url):
    target = urlparse(target_url)

    timings = {
        "tcp_connection": [],
        "proxy_connect": [],
        "tls_negotiation": [],
        "handshake": [],
        "https_get": [],
        "total": []
    }

    for _ in range(NUM_REQUESTS):
        try:
            # Start total timer
            total_start = time.time()

            # TCP Connection
            tcp_start = time.time()
            if proxy_url:
                proxy = urlparse(proxy_url)
                sock = socks.socksocket()

                if proxy.scheme == "socks5":
                    sock.set_proxy(
                        socks.SOCKS5,
                        proxy.hostname,
                        proxy.port,
                        username=proxy.username,
                        password=proxy.password,
                    )
                elif proxy.scheme == "http":
                    sock.set_proxy(
                        socks.HTTP,
                        proxy.hostname,
                        proxy.port,
                        username=proxy.username,
                        password=proxy.password,
                    )
                else:
                    raise ValueError(f"Unsupported proxy scheme: {proxy.scheme}")
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.connect((target.hostname, target.port or 443))
            tcp_end = time.time()

            # Proxy CONNECT (already handled by PySocks for SOCKS5 and HTTP)
            proxy_start = time.time()
            proxy_end = time.time()

            # TLS Negotiation
            tls_start = time.time()
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target.hostname)
            tls_end = time.time()

            # Handshake (if applicable)
            handshake_start = time.time()
            # Simulate handshake (already done in TLS negotiation)
            handshake_end = time.time()

            # HTTPS GET
            https_start = time.time()
            request = f"GET {target.path or '/'} HTTP/1.1\r\nHost: {target.hostname}\r\n\r\n"
            sock.sendall(request.encode("utf-8"))
            response = sock.recv(4096)  # Read the response to complete the request
            https_end = time.time()

            # Total time
            total_end = time.time()

            # Record timings
            timings["tcp_connection"].append((tcp_end - tcp_start) * 1000)
            timings["proxy_connect"].append((proxy_end - proxy_start) * 1000)
            timings["tls_negotiation"].append((tls_end - tls_start) * 1000)
            timings["handshake"].append((handshake_end - handshake_start) * 1000)
            timings["https_get"].append((https_end - https_start) * 1000)
            timings["total"].append((total_end - total_start) * 1000)

            sock.close()

        except Exception as e:
            print(f"Error: {e}")
            continue

    # Print results
    print("\nStage\t\tMin\tMed\tAvg\tMax\tStdDev")
    for stage, times in timings.items():
        if times:
            print(
                f"{stage.capitalize():<15}"
                f"{min(times):.0f}ms\t"
                f"{statistics.median(times):.0f}ms\t"
                f"{statistics.mean(times):.0f}ms\t"
                f"{max(times):.0f}ms\t"
                f"{statistics.stdev(times):.0f}ms"
            )

# Main script
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python proxy_timing.py <target_url> [<proxy_url>]")
        sys.exit(1)

    target_url = sys.argv[1]
    proxy_url = sys.argv[2] if len(sys.argv) == 3 else None

    print(f"Making {NUM_REQUESTS} requests to {target_url} via {proxy_url or 'direct connection'}")
    measure_request(proxy_url, target_url)
