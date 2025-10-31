import socket, json, os, argparse, base64, pathlib
from crypto_utils import P, G, int_to_b64, b64_to_int, hkdf_keys, aes_gcm_encrypt, hmac_sha256, validate_file

def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def recv_msg(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    n = int.from_bytes(raw_len, 'big')
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def main(host, port, file_path, wrong_key=False):
    # Validação básica do arquivo
    safe_name, size, mime = validate_file(file_path)
    print(f"[CLIENT] Sending file: {safe_name} ({size} bytes), type={mime}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[CLIENT] Connected to {host}:{port}")

    # Recebe parâmetros DH do servidor
    hello = recv_msg(sock)
    assert hello["type"] == "hello"
    P_recv = b64_to_int(hello["p"])
    assert P_recv == P and hello["g"] == G, "Unexpected DH group"
    A = b64_to_int(hello["A"])

    # Envia B do cliente (base64 + hex)
    b = int.from_bytes(os.urandom(32), 'big')
    B = pow(G, b, P)
    send_msg(sock, {
        "type":"dh_pub",
        "B": int_to_b64(B),
        "B_hex": format(B, "x") # B em hexadecimal para aparecer no Wireshark
    })
    print("[CLIENT] Sent B (base64+hex).")

    # Deriva chaves a partir do segredo compartilhado
    ssec = pow(A, b, P)
    if wrong_key:
        ssec ^= 1  # Simula chave errada
        print("[CLIENT] (Simulating wrong key)")

    aes_key, mac_key = hkdf_keys(ssec, info=b"client")
    print("[CLIENT] Shared secret established. Keys derived.")

    # Cifra arquivo + HMAC
    data = read_bytes(file_path)
    header = {
        "filename": safe_name,
        "filesize": size,
        "mimetype": mime,
        "algo": "AES-256-GCM",
        "hash_algo": "HMAC-SHA256",
    }
    aad = json.dumps(header, separators=(',',':')).encode()
    enc = aes_gcm_encrypt(aes_key, data, aad=aad)
    blob = json.dumps(enc, separators=(',',':')).encode()
    mac = hmac_sha256(mac_key, aad + b"|" + blob)

    send_msg(sock, {"type":"file_pkg","header":header,"enc":enc,"hmac":mac})
    print("[CLIENT] Encrypted file + HMAC sent. Awaiting result...")

    result = recv_msg(sock)
    print(f"[CLIENT] Server response: {result}")

    sock.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Secure file client (DH + AES-GCM + HMAC)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--file", required=True, help="Path to file to send")
    ap.add_argument("--wrong-key", action="store_true", help="Simulate decryption failure by deriving a wrong key")
    args = ap.parse_args()
    main(args.host, args.port, args.file, wrong_key=args.wrong_key)