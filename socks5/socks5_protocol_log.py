import os
import socket
import struct
import logging
import sys
import argparse
from dnslib import DNSRecord
from dotenv import load_dotenv
load_dotenv()


SOCKS5_SERVER = os.getenv('SOCKS5_SERVER', '0.0.0.0')
SOCKS5_PORT = int(os.getenv('SOCKS5_PORT', 1080))
SOCKS5_USERNAME = os.getenv('SOCKS5_USERNAME', '')
SOCKS5_PASSWORD = os.getenv('SOCKS5_PASSWORD', '')

# Log config
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def send_greeting(sock):
    """Greeting message to SOCKS5."""
    if SOCKS5_USERNAME and SOCKS5_PASSWORD:
        methods = [0x00, 0x02]
    else:
        methods = [0x00]

    greeting = struct.pack('!BB', 0x05, len(methods)) + bytes(methods)
    sock.sendall(greeting)
    logging.debug(f'Greeting sent: {greeting}')


def receive_greeting_response(sock):
    """Receiving a response to a greeting from a SOCKS5 server."""
    response = sock.recv(2)
    version, method = struct.unpack('!BB', response)
    logging.debug(
        f'Received a response to the greeting: version={version}, method={method}')
    if version != 0x05:
        raise Exception('Invalid SOCKS version.')
    if method == 0xFF:
        raise Exception('No supported authentication methods.')
    return method


def authenticate(sock):
    """Passing authentication on a SOCKS5 server."""
    username = SOCKS5_USERNAME.encode('utf-8')
    password = SOCKS5_PASSWORD.encode('utf-8')
    auth_request = struct.pack('!B', 0x01) + struct.pack('!B', len(username)) + \
        username + struct.pack('!B', len(password)) + password
    sock.sendall(auth_request)
    logging.debug(f'Authentication request sent: {auth_request}')

    response = sock.recv(2)
    version, status = struct.unpack('!BB', response)
    logging.debug(
        f'Authentication response received: version={version}, status={status}')
    if status != 0x00:
        raise Exception('Authentication failed.')


def send_udp_associate(sock, bind_addr='0.0.0.0', bind_port=0):
    """Sending UDP ASSOCIATE command to SOCKS5 server."""
    addr = socket.inet_aton(bind_addr)
    port = struct.pack('!H', bind_port)
    request = struct.pack('!BBB', 0x05, 0x03, 0x00) + \
        struct.pack('!B', 0x01) + addr + port
    sock.sendall(request)
    logging.debug(f'UDP ASSOCIATE request sent: {request}')

    response = sock.recv(10)
    logging.debug(f'UDP ASSOCIATE response size: {len(response)}')

    version, rep, rsv, atyp = struct.unpack('!BBBB', response[:4])
    logging.debug(
        f'UDP ASSOCIATE response received: version={version}, response={rep}, reserve={rsv}, address type={atyp}')
    if rep != 0x00:
        raise Exception('UDP ASSOCIATE failed.')
    
    if atyp == 0x01:  # IPv4
        bind_address = socket.inet_ntoa(response[4:8])
        bind_port = struct.unpack('!H', response[8:10])[0]
    else:
        raise Exception('Unsupported address type in response.')

    logging.info(f'UDP ASSOCIATE is set to {bind_address}:{bind_port}')
    return bind_address, bind_port


def create_udp_socket():
    """Creating a UDP socket."""
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return udp_sock


def send_udp_packet(udp_sock, proxy_addr, proxy_port, dest_addr, dest_port, data):
    """Sending UDP packet via SOCKS5 proxy."""
    reserved = b'\x00\x00'
    frag = b'\x00'
    atyp = b'\x01'  # IPv4
    addr = socket.inet_aton(dest_addr)
    port = struct.pack('!H', dest_port)

    udp_header = reserved + frag + atyp + addr + port
    packet = udp_header + data

    udp_sock.sendto(packet, (proxy_addr, proxy_port))
    logging.debug(
        f'UDP packet sent via proxy to {proxy_addr}:{proxy_port} with data: {packet}')


def receive_udp_packet(udp_sock):
    """Receiving UDP packet via SOCKS5 proxy."""
    data, addr = udp_sock.recvfrom(65535)
    logging.debug(f'Received UDP packet from {addr} with data: {data}')

    reserved, frag, atyp = data[:2], data[2:3], data[3:4]
    if reserved != b'\x00\x00' or frag != b'\x00':
        logging.warning('Invalid packet received.')
        return None, None, None

    if atyp == b'\x01':  # IPv4
        dest_addr = socket.inet_ntoa(data[4:8])
        dest_port = struct.unpack('!H', data[8:10])[0]
        payload = data[10:]
    else:
        logging.warning('Unsupported address type in received packet.')
        return None, None, None

    logging.info(
        f'Received a UDP packet through a proxy from {dest_addr}:{dest_port} with data: {payload}')
    return dest_addr, dest_port, payload


def send_tcp_connect(sock, dest_addr, dest_port):
    """Sending CONNECT command for TCP connection via SOCKS5 proxy."""
    addr = socket.inet_aton(dest_addr)
    port = struct.pack('!H', dest_port)
    request = struct.pack('!BBB', 0x05, 0x01, 0x00) + \
        struct.pack('!B', 0x01) + addr + port
    sock.sendall(request)
    logging.debug(f'CONNECT request sent: {request}')

    response = sock.recv(10)
    version, rep, rsv, atyp = struct.unpack('!BBBB', response[:4])
    logging.debug(
        f'CONNECT response received: version={version}, response={rep}, reserve={rsv}, address type={atyp}')
    if rep != 0x00:
        raise Exception('CONNECT failed.')

    logging.info(f'TCP CONNECT established with {dest_addr}:{dest_port}')


def main():
    parser = argparse.ArgumentParser(
        description='SOCKS5 test client with logging of SOCKS5 commands.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--udp', help='Create a test UDP connection to the specified address (ip:port format)')
    group.add_argument(
        '--tcp', help='Create a test TCP connection to the specified address (ip:port format)')

    args = parser.parse_args()

    try:
        # Парсинг адреса и порта назначения
        if args.udp:
            dest_ip, dest_port = args.udp.split(':')
            dest_port = int(dest_port)
            mode = 'udp'
        elif args.tcp:
            dest_ip, dest_port = args.tcp.split(':')
            dest_port = int(dest_port)
            mode = 'tcp'
        else:
            raise Exception('Destination address not specified.')

        # Устанавливаем TCP-соединение с SOCKS5-сервером
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((SOCKS5_SERVER, SOCKS5_PORT))
        logging.info('TCP connection to SOCKS5 server established.')

        # Инициализация SOCKS5
        send_greeting(tcp_sock)
        method = receive_greeting_response(tcp_sock)
        if method == 0x02:
            authenticate(tcp_sock)

        if mode == 'udp':
            # Отправляем команду UDP ASSOCIATE
            proxy_udp_addr, proxy_udp_port = send_udp_associate(tcp_sock)

            # Согласно RFC 1928 (спецификация SOCKS5):
            # "In the reply to a UDP ASSOCIATE request, the BND.ADDR and BND.PORT fields indicate the address and port that the client should use to send UDP datagrams."
            if proxy_udp_addr == "0.0.0.0":
                proxy_udp_addr = SOCKS5_SERVER
                # Создаем UDP-сокет
            udp_sock = create_udp_socket()

            dns_query = DNSRecord.question("www.example.com")

            # Пример данных для отправки
            # test_data = b'\x00' * 10  # Любые данные

            test_data = dns_query.pack()

            # Отправляем UDP-пакет через прокси
            send_udp_packet(udp_sock, proxy_udp_addr,
                            proxy_udp_port, dest_ip, dest_port, test_data)

            # Ожидание ответа
            udp_sock.settimeout(5)
            try:
                dest_addr, dest_port, payload = receive_udp_packet(udp_sock)
                if payload:
                    logging.info(
                        f'Received a response from {dest_addr}:{dest_port} with data: {payload}')
            except socket.timeout:
                logging.warning('No response received within timeout.')
            finally:
                udp_sock.close()

        elif mode == 'tcp':
            # Отправляем команду CONNECT для TCP-подключения
            send_tcp_connect(tcp_sock, dest_ip, dest_port)

            # Отправляем данные через установленное TCP-соединение
            http_request = f"GET / HTTP/1.1\r\nHost: {dest_ip}\r\nConnection: close\r\n\r\n"
            test_data = http_request.encode('utf-8')
            tcp_sock.sendall(test_data)
            logging.debug(f'Data sent: {test_data}')

            # Получаем ответ
            tcp_sock.settimeout(5)
            try:
                response = tcp_sock.recv(4096)
                if response:
                    logging.info(f'Response received: {response}')
            except socket.timeout:
                logging.warning('No response received within timeout.')

        tcp_sock.close()
        logging.info('Connection to SOCKS5 server closed.')

    except Exception as e:
        logging.error(f'Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
