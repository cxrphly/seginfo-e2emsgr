"""
Cliente de mensageria segura E2E.

Protocolo:
  1. Gera par efêmero X25519 (sk_client / pk_client)
  2. Handshake com o servidor: envia client_id + pk_client
  3. Recebe cert RSA + assinatura + salt_srv; valida RSA-PSS
  4. Para cada peer: deriva Key_A2B e Key_B2A via HKDF-SHA256
  5. Troca mensagens cifradas com AES-128-GCM

Estrutura peers[peer_id]:
  pk, salt, key_send, key_recv,
  seq_send, seq_recv, iv_base_send
"""
import asyncio
import logging
import os
import struct
import sys
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apd
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509

HANDSHAKE = 0x01
HANDSHAKE_RESP = 0x02
PEER_KEY = 0x03
E2E = 0x04
DISCONNECT = 0x05
MAX_PLAINTEXT = 4096

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLI] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

def build_frame(msg_type: int, payload: bytes) -> bytes:
    body = bytes([msg_type]) + payload
    return struct.pack(">I", len(body)) + body

async def read_frame(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(4)
    n = struct.unpack(">I", hdr)[0]
    if n > 65_536:
        raise ValueError(f"frame muito grande: {n}")
    return await reader.readexactly(n)
#criptografia end to end
def _derive_e2e_keys(
    my_id: bytes,
    peer_id: bytes,
    sk: X25519PrivateKey,
    pk_peer_bytes: bytes,
    my_salt: bytes,
    peer_salt: bytes,
) -> tuple[bytes, bytes]:
    """
    retorna (key_send, key_recv) usado para ordenacao 
    key_send = HKDF(salt=my_salt,   IKM=Z, info="A2B")
    key_recv = HKDF(salt=peer_salt, IKM=Z, info="B2A")
    """
    Z = sk.exchange(X25519PublicKey.from_public_bytes(pk_peer_bytes))
    is_A = my_id < peer_id

    send_info = b"A2B" if is_A else b"B2A"
    recv_info = b"B2A" if is_A else b"A2B"

    key_send = HKDF(hashes.SHA256(), 16, my_salt,   send_info).derive(Z)
    key_recv = HKDF(hashes.SHA256(), 16, peer_salt, recv_info).derive(Z)

    return key_send, key_recv


def _encrypt(
    key: bytes,
    sender_id: bytes,
    recipient_id: bytes,
    seq_no: int,
    plaintext: bytes,
    iv_base: bytes,
) -> bytes:
    """
    Retorna: nonce(12) + sender_id(16) + recipient_id(16) + seq_no(8) + ciphertext+tag(N+16)
    AAD = sender_id || recipient_id || seq_no (garante integridade dos metadados)
    """
    seq_bytes = struct.pack(">Q", seq_no)
    nonce = iv_base + seq_bytes # 4B || 8B = 12B
    aad = sender_id + recipient_id + seq_bytes
    ct = AESGCM(key).encrypt(nonce, plaintext, aad) # inclui tag GCM de 16B
    return nonce + sender_id + recipient_id + seq_bytes + ct


def _decrypt(
    key: bytes,
    payload: bytes,
    my_id: bytes,
    last_seq: int,
) -> tuple[bytes, int, bytes]:
    """
    payload = nonce(12) + sender_id(16) + recipient_id(16) + seq_no(8) + ciphertext+tag
    Retorna (sender_id, seq_no, plaintext) ou lança exceção.
    """

    if len(payload) < 68: # 12+16+16+8+16
        raise ValueError("payload E2E curto demais")
    #extracao
    nonce        = payload[:12]
    sender_id    = payload[12:28]
    recipient_id = payload[28:44]
    seq_bytes    = payload[44:52]
    ciphertext   = payload[52:]

    seq_no = struct.unpack(">Q", seq_bytes)[0]


    if recipient_id != my_id:
        raise ValueError("recipient_id não corresponde a este cliente")
    if seq_no <= last_seq:
        raise ValueError(f"replay detectado: seq={seq_no} último aceito={last_seq}")
    #verificar gcm
    aad       = sender_id + recipient_id + seq_bytes
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    return sender_id, seq_no, plaintext


class SecureClient:
    def __init__(self):
        self.client_id: bytes = uuid.uuid4().bytes #uuid unico para sessao
        self.sk: X25519PrivateKey = X25519PrivateKey.generate() #par de chaves, troca por sessao
        self.pk: bytes = self.sk.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.my_salt: bytes | None = None
        self.peers: dict[bytes, dict] = {}
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None


    async def connect_and_handshake(self, host: str, port: int):
        self.reader, self.writer = await asyncio.open_connection(host, port)

        # envia [1B tipo][16B client_id][32B pk_client]
        self.writer.write(build_frame(HANDSHAKE, self.client_id + self.pk))
        await self.writer.drain()

        # Recebe resposta do servidor
        raw = await asyncio.wait_for(read_frame(self.reader), timeout=10.0)
        if raw[0] != HANDSHAKE_RESP:
            raise ValueError(f"tipo inesperado {raw[0]:#x}, esperado HANDSHAKE_RESP")

        p = raw[1:]
        cert_len = struct.unpack(">I", p[:4])[0]
        cert_pem = p[4 : 4 + cert_len]
        p        = p[4 + cert_len :]
        sig_len  = struct.unpack(">I", p[:4])[0]
        sig      = p[4 : 4 + sig_len]
        salt_srv = p[4 + sig_len : 4 + sig_len + 16]

        if len(salt_srv) != 16:
            raise ValueError("salt_srv ausente ou incompleto na resposta")

        # verificar certificado do servidor
        with open("server.crt", "rb") as f:
            pinned_pem = f.read()
        if cert_pem != pinned_pem:
            raise ValueError("Certificado do servidor NÃO corresponde ao pinado!")

        cert      = x509.load_pem_x509_certificate(cert_pem)
        pk_server = cert.public_key()
        pk_s_der  = pk_server.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # verificar assinatura rsa
        try:
            pk_server.verify(
                sig,
                pk_s_der + self.pk + self.client_id + salt_srv,
                apd.PSS(
                    mgf=apd.MGF1(hashes.SHA256()),
                    salt_length=apd.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception:
            raise ValueError("Assinatura RSA-PSS do servidor INVÁLIDA — possível MITM!")

        self.my_salt = salt_srv
        log.info(f"Handshake OK. Meu ID: {self.client_id.hex()}")

    # gerenciar peers  
    def _add_peer(self, peer_id: bytes, pk_peer: bytes, peer_salt: bytes):
        key_send, key_recv = _derive_e2e_keys(
            self.client_id, peer_id, self.sk, pk_peer, self.my_salt, peer_salt
        )
        self.peers[peer_id] = {
            "pk":           pk_peer,
            "salt":         peer_salt,
            "key_send":     key_send,
            "key_recv":     key_recv,
            "seq_send":     0,
            "seq_recv":     -1,
            "iv_base_send": os.urandom(4),
        }
        log.info(f"Peer adicionado: {peer_id.hex()[:16]}...")

    async def send_message(self, peer_id: bytes, text: str):
        plaintext = text.encode("utf-8")
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError(f"Mensagem muito longa (máx {MAX_PLAINTEXT} bytes)")

        peer = self.peers.get(peer_id)
        if not peer:
            raise KeyError(f"Peer desconhecido: {peer_id.hex()[:8]}")

        seq = peer["seq_send"]
        peer["seq_send"] += 1

        e2e_payload = _encrypt(
            peer["key_send"],
            self.client_id,
            peer_id,
            seq,
            plaintext,
            peer["iv_base_send"],
        )
        self.writer.write(build_frame(E2E, e2e_payload))
        await self.writer.drain()

    async def recv_loop(self, event_queue: asyncio.Queue):
        while True:
            raw = await read_frame(self.reader)
            t   = raw[0]
            p   = raw[1:]

            if t == PEER_KEY:
                # [16B peer_id][32B pk][16B salt]
                if len(p) == 64:
                    pid   = p[:16]
                    pk    = p[16:48]
                    psalt = p[48:64]
                    self._add_peer(pid, pk, psalt)
                    await event_queue.put(("system", f"Novo peer: {pid.hex()[:16]}..."))
                else:
                    log.warning(f"PEER_KEY com tamanho inesperado: {len(p)}")

            elif t == E2E:
                sender_id = p[12:28]
                peer = self.peers.get(sender_id)
                if not peer:
                    log.warning(f"Mensagem de peer desconhecido: {sender_id.hex()[:8]}")
                    continue
                try:
                    sid, seq_no, plaintext = _decrypt(
                        peer["key_recv"], p, self.client_id, peer["seq_recv"]
                    )
                    peer["seq_recv"] = seq_no
                    text = plaintext.decode("utf-8", errors="replace")
                    await event_queue.put(("msg", sid, text))
                except Exception as e:
                    log.warning(f"Erro ao decifrar mensagem de {sender_id.hex()[:8]}: {e}")

            elif t == DISCONNECT:
                pid = p[:16]
                self.peers.pop(pid, None)
                await event_queue.put(("system", f"Peer desconectado: {pid.hex()[:16]}..."))

            else:
                log.warning(f"Tipo de frame desconhecido: {t:#x}")

async def _printer(queue: asyncio.Queue):
    while True:
        ev = await queue.get()
        if ev[0] == "system":
            print(f"\n[SISTEMA] {ev[1]}")
        elif ev[0] == "msg":
            sender = ev[1].hex()[:16]
            print(f"\n[{sender}...] {ev[2]}")
        sys.stdout.flush()


async def _stdin_task(in_queue: asyncio.Queue):
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            await in_queue.put(None)
            return
        await in_queue.put(line.rstrip("\n"))


async def main():
    client = SecureClient()
    print(f"Meu client_id: {client.client_id.hex()}")

    await client.connect_and_handshake("127.0.0.1", 8888)

    event_q = asyncio.Queue()
    recv_task   = asyncio.create_task(client.recv_loop(event_q))
    print_task  = asyncio.create_task(_printer(event_q))

    in_queue = asyncio.Queue()
    asyncio.create_task(_stdin_task(in_queue))

    print("\nComandos:")
    print("  list              – lista peers conectados")
    print("  @<N> <mensagem>  – envia mensagem ao peer de índice N")
    print("  <mensagem>        – envia ao primeiro peer (se único)")
    print("  quit              – encerra\n")

    while True:
        line: str | None = await in_queue.get()
        if line is None:
            break
        line = line.strip()
        if not line:
            continue

        if line == "quit":
            break

        if line == "list":
            peer_list = list(client.peers.keys())
            if not peer_list:
                print("[SISTEMA] Nenhum peer conectado.")
            for i, pid in enumerate(peer_list):
                print(f"  [{i}] {pid.hex()}")
            continue

        if line.startswith("@"):
            rest = line[1:]
            parts = rest.split(" ", 1)
            try:
                idx  = int(parts[0])
                text = parts[1] if len(parts) > 1 else ""
                peer_list = list(client.peers.keys())
                if idx < 0 or idx >= len(peer_list):
                    print(f"[SISTEMA] Índice inválido: {idx}")
                    continue
                pid = peer_list[idx]
                await client.send_message(pid, text)
                print(f"[eu -> {pid.hex()[:8]}] {text}")
            except (ValueError, KeyError) as e:
                print(f"[SISTEMA] Erro: {e}")
            continue
    

        peer_list = list(client.peers.keys())
        
        if not peer_list:
            print("[SISTEMA] Nenhum peer disponível. Aguarde uma conexão.")
            continue
        if len(peer_list) == 1:
            pid = peer_list[0]
            try:
                await client.send_message(pid, line)
                print(f"[eu -> {pid.hex()[:8]}] {line}")
            except Exception as e:
                print(f"[SISTEMA] Erro ao enviar: {e}")
        else:
            print("[SISTEMA] Múltiplos peers. Use @<índice> <mensagem> ou 'list'.")



    recv_task.cancel()
    print_task.cancel()
    try:
        client.writer.close()
        await client.writer.wait_closed()
    except Exception:
        pass
    print("Conexão encerrada.")


if __name__ == "__main__":
    asyncio.run(main())
