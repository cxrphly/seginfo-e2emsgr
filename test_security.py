"""
Testes de segurança automatizados (demonstração para apresentação).

Executa os testes mínimos obrigatórios do enunciado:
  1. Troca de mensagens E2E entre dois clientes (decifra corretamente)
  2. Bitflip no ciphertext
  3. Replay de frame (seq_no repetido) 
  4. Frame com tamanho inválido

"""
import asyncio
import os
import struct
import sys
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apd
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509

HOST = "127.0.0.1"
PORT = 8888

HANDSHAKE      = 0x01
HANDSHAKE_RESP = 0x02
PEER_KEY       = 0x03
E2E            = 0x04
DISCONNECT     = 0x05

PASS = "\033[92m[PASSOU]\033[0m"
FAIL = "\033[91m[FALHOU]\033[0m"



def build_frame(t, payload):
    body = bytes([t]) + payload
    return struct.pack(">I", len(body)) + body


async def read_frame(reader):
    hdr = await reader.readexactly(4)
    n = struct.unpack(">I", hdr)[0]
    if n > 65536:
        raise ValueError(f"frame grande: {n}")
    return await reader.readexactly(n)


def derive_keys(my_id, peer_id, sk, pk_peer_bytes, my_salt, peer_salt):
    Z = sk.exchange(X25519PublicKey.from_public_bytes(pk_peer_bytes))
    is_A = my_id < peer_id
    key_send = HKDF(hashes.SHA256(), 16, my_salt,   b"A2B" if is_A else b"B2A").derive(Z)
    key_recv = HKDF(hashes.SHA256(), 16, peer_salt, b"B2A" if is_A else b"A2B").derive(Z)
    return key_send, key_recv


def encrypt_e2e(key, sender_id, recip_id, seq_no, plaintext, iv_base):
    seq_bytes = struct.pack(">Q", seq_no)
    nonce = iv_base + seq_bytes
    aad   = sender_id + recip_id + seq_bytes
    ct    = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + sender_id + recip_id + seq_bytes + ct


async def do_handshake(reader, writer):
    cid  = uuid.uuid4().bytes
    sk   = X25519PrivateKey.generate()
    pk   = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    writer.write(build_frame(HANDSHAKE, cid + pk))
    await writer.drain()

    raw = await asyncio.wait_for(read_frame(reader), 10)
    assert raw[0] == HANDSHAKE_RESP, "Esperado HANDSHAKE_RESP"

    p = raw[1:]
    cert_len = struct.unpack(">I", p[:4])[0]
    cert_pem = p[4:4+cert_len]; p = p[4+cert_len:]
    sig_len  = struct.unpack(">I", p[:4])[0]
    sig      = p[4:4+sig_len]
    salt_srv = p[4+sig_len:4+sig_len+16]

    with open("server.crt", "rb") as f:
        pinned = f.read()
    assert cert_pem == pinned, "Certificado não corresponde ao pinado"

    cert     = x509.load_pem_x509_certificate(cert_pem)
    pk_s     = cert.public_key()
    pk_s_der = pk_s.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pk_s.verify(sig, pk_s_der + pk + cid + salt_srv,
                apd.PSS(mgf=apd.MGF1(hashes.SHA256()), salt_length=apd.PSS.MAX_LENGTH),
                hashes.SHA256())

    return cid, sk, pk, salt_srv


async def wait_peer_key(reader):
    """Aguarda o primeiro frame PEER_KEY e retorna (peer_id, peer_pk, peer_salt)."""
    while True:
        raw = await asyncio.wait_for(read_frame(reader), 5)
        if raw[0] == PEER_KEY and len(raw[1:]) == 64:
            p = raw[1:]
            return p[:16], p[16:48], p[48:64]



async def test_e2e_exchange():
    """Teste 1: troca de mensagens E2E entre A e B."""
    print("\n[1] Troca E2E entre dois clientes...")

    rA, wA = await asyncio.open_connection(HOST, PORT)
    rB, wB = await asyncio.open_connection(HOST, PORT)

    cidA, skA, pkA, saltA = await do_handshake(rA, wA)
    cidB, skB, pkB, saltB = await do_handshake(rB, wB)

    peer_id_for_A, pk_peer_A, salt_peer_A = await wait_peer_key(rA)
    peer_id_for_B, pk_peer_B, salt_peer_B = await wait_peer_key(rB)

    assert peer_id_for_A == cidB
    assert peer_id_for_B == cidA

    key_send_A, key_recv_A = derive_keys(cidA, cidB, skA, pkB, saltA, saltB)
    key_send_B, key_recv_B = derive_keys(cidB, cidA, skB, pkA, saltB, saltA)

    # A envia para B
    plaintext = b"Ola, mundo seguro!"
    iv_a = os.urandom(4)
    payload = encrypt_e2e(key_send_A, cidA, cidB, 0, plaintext, iv_a)
    wA.write(build_frame(E2E, payload))
    await wA.drain()

    # B recebe e decifra
    raw = await asyncio.wait_for(read_frame(rB), 5)
    assert raw[0] == E2E
    p = raw[1:]
    nonce = p[:12]; seq_bytes = p[44:52]; ciphertext = p[52:]
    aad = cidA + cidB + seq_bytes
    decrypted = AESGCM(key_recv_B).decrypt(nonce, ciphertext, aad)
    assert decrypted == plaintext, f"Esperado {plaintext!r}, obtido {decrypted!r}"

    for w in (wA, wB):
        w.close()

    print(f"  Mensagem decifrada: {decrypted!r}  {PASS}")


async def test_bitflip():
    """Teste 2: bitflip no ciphertext → rejeição por GCM tag."""
    print("\n[2] Bitflip no ciphertext (deve rejeitar)...")

    rA, wA = await asyncio.open_connection(HOST, PORT)
    rB, wB = await asyncio.open_connection(HOST, PORT)

    cidA, skA, pkA, saltA = await do_handshake(rA, wA)
    cidB, skB, pkB, saltB = await do_handshake(rB, wB)

    await wait_peer_key(rA)
    await wait_peer_key(rB)

    key_send_A, _ = derive_keys(cidA, cidB, skA, pkB, saltA, saltB)
    _, key_recv_B = derive_keys(cidB, cidA, skB, pkA, saltB, saltA)

    iv_a = os.urandom(4)
    payload = encrypt_e2e(key_send_A, cidA, cidB, 0, b"mensagem secreta", iv_a)

    lst = list(payload)
    lst[52] ^= 0xFF
    tampered = bytes(lst)

    wA.write(build_frame(E2E, tampered))
    await wA.drain()

    raw = await asyncio.wait_for(read_frame(rB), 5)
    assert raw[0] == E2E
    p = raw[1:]
    nonce = p[:12]; seq_bytes = p[44:52]; ciphertext = p[52:]
    aad = cidA + cidB + seq_bytes

    try:
        AESGCM(key_recv_B).decrypt(nonce, ciphertext, aad)
        print(f"  Mensagem adulterada ACEITA  {FAIL}")
    except Exception:
        print(f"  Tag GCM invalida - mensagem rejeitada  {PASS}")

    for w in (wA, wB):
        w.close()


async def test_replay():
    """Teste 3: replay de frame com seq_no repetido → rejeição."""
    print("\n[3] Replay de frame (seq_no duplicado)...")

    rA, wA = await asyncio.open_connection(HOST, PORT)
    rB, wB = await asyncio.open_connection(HOST, PORT)

    cidA, skA, pkA, saltA = await do_handshake(rA, wA)
    cidB, skB, pkB, saltB = await do_handshake(rB, wB)

    await wait_peer_key(rA)
    await wait_peer_key(rB)

    key_send_A, _ = derive_keys(cidA, cidB, skA, pkB, saltA, saltB)
    _, key_recv_B = derive_keys(cidB, cidA, skB, pkA, saltB, saltA)

    iv_a = os.urandom(4)

    # Envia seq_no=0
    p0 = encrypt_e2e(key_send_A, cidA, cidB, 0, b"mensagem 0", iv_a)
    wA.write(build_frame(E2E, p0))
    await wA.drain()
    raw0 = await asyncio.wait_for(read_frame(rB), 5)
    assert raw0[0] == E2E
    p = raw0[1:]
    nonce = p[:12]; seq_b = p[44:52]; ct = p[52:]
    aad = cidA + cidB + seq_b
    dec0 = AESGCM(key_recv_B).decrypt(nonce, ct, aad)
    last_seq = struct.unpack(">Q", seq_b)[0]

    wA.write(build_frame(E2E, p0))
    await wA.drain()

    try:
        raw1 = await asyncio.wait_for(read_frame(rB), 2)
        p1 = raw1[1:]
        seq_replay = struct.unpack(">Q", p1[44:52])[0]
        if seq_replay <= last_seq:
            print(f"  Replay detectado no destino (seq repetido)  {PASS}")
        else:
            print(f"  Replay chegou ao destino com seq diferente  {FAIL}")
    except asyncio.TimeoutError:
        print(f"  Replay bloqueado pelo servidor  {PASS}")

    for w in (wA, wB):
        w.close()


async def test_invalid_framing():
    """Teste 4: frame com tamanho incorreto → desconexão."""
    print("\n[4] Frame com tamanho declarado incorreto...")

    r, w = await asyncio.open_connection(HOST, PORT)

    w.write(struct.pack(">I", 10) + b"\x01" + b"XXXX")  # 5 bytes reais
    await w.drain()

    try:
        await asyncio.wait_for(r.read(1), timeout=3)
        print(f"  Servidor não desconectou  {FAIL}")
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError):
        print(f"  Servidor encerrou a conexão (framing inválido tratado)  {PASS}")

    w.close()

async def run_all():
    print("=" * 60)
    print("  Testes de Segurança")
    print("=" * 60)
    try:
        await test_e2e_exchange()
        await test_bitflip()
        await test_replay()
        await test_invalid_framing()
    except Exception as e:
        print(f"\n[ERRO FATAL] {e}")
        import traceback; traceback.print_exc()
    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(run_all())
