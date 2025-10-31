import socket, json, os, argparse, base64, time
from crypto_utils import P, G, int_to_b64, b64_to_int, hkdf_keys, aes_gcm_decrypt, hmac_sha256

def send_msg(conn, obj):
    data = json.dumps(obj).encode()
    conn.sendall(len(data).to_bytes(4, 'big') + data)

def recv_msg(conn):
    raw_len = conn.recv(4)
    if not raw_len:
        return None
    n = int.from_bytes(raw_len, 'big')
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return json.loads(data.decode())

def main(host, port, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"[SERVER] Listening on {host}:{port} ...")

    conn, addr = s.accept()
    with conn:
        print(f"[SERVER] Connected by {addr}")

        # Diffie-Hellman
        a = int.from_bytes(os.urandom(32), 'big')
        A = pow(G, a, P)
        hello = {
            "type": "hello",
            # Formatos para aparecerem visíveis no Wireshark
            "p": int_to_b64(P),
            "p_hex": format(P, "x"),
            "g": G,
            "A": int_to_b64(A),    
            "A_hex": format(A, "x")
        }
        send_msg(conn, hello)
        print("[SERVER] Sent DH params (p,g) and A (base64+hex)")

        # Recebe B e deriva segredo compartilhado
        msg = recv_msg(conn)
        assert msg["type"] == "dh_pub", "Expected dh_pub"
        B = b64_to_int(msg["B"])
        ssec = pow(B, a, P)
        aes_key, mac_key = hkdf_keys(ssec, info=b"server")
        print("[SERVER] Shared secret established. Keys derived.")

        # Recebe o pacote cifrado + HMAC
        pkg = recv_msg(conn)
        assert pkg["type"] == "file_pkg", "Expected file_pkg"
        header = pkg["header"]
        enc = pkg["enc"]
        recv_hmac = pkg["hmac"]

        aad = json.dumps(header, separators=(',',':')).encode()
        blob = json.dumps(enc, separators=(',',':')).encode()
        calc_hmac = hmac_sha256(mac_key, aad + b"|" + blob)

        if calc_hmac != recv_hmac:
            print("[SERVER] HMAC verification FAILED! Possible tampering or wrong key.")
            send_msg(conn, {"type":"result","ok":False,"reason":"HMAC_FAIL"})
            return

        try:
            plaintext = aes_gcm_decrypt(aes_key, enc, aad=aad)
        except Exception as e:
            print(f"[SERVER] Decryption failed: {e}")
            send_msg(conn, {"type":"result","ok":False,"reason":"DECRYPT_FAIL"})
            return

        fname = header["filename"]
        out_path = os.path.join(out_dir, fname)
        with open(out_path, "wb") as f:
            f.write(plaintext)

        print(f"[SERVER] File received and saved to {out_path} ({len(plaintext)} bytes).")
        send_msg(conn, {"type":"result","ok":True,"saved_as":fname,"bytes":len(plaintext)})
        time.sleep(0.2)

    s.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Secure file server (DH + AES-GCM + HMAC)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--out", default="received")
    args = ap.parse_args()
    main(args.host, args.port, args.out)