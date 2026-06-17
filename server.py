"""
Servidor relay de mensageria segura E2E.
Autentica clientes via RSA-PSS, distribui chaves públicas X25519,
encaminha frames cifrados sem decifrar o conteúdo.
"""
import asyncio
import logging
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apd

# frames
HANDSHAKE  = 0x01 # cliente -> servidor: client_id + pk_client
HANDSHAKE_RESP = 0x02 # servidor -> cliente: cert + sig + salt
PEER_KEY = 0x03 # servidor -> cliente: peer_id + pk_peer + salt_peer
E2E = 0x04 # cliente <-> cliente
DISCONNECT = 0x05 #servidor -> cliente

MAX_FRAME = 12_000 #cert PEM + assinatura + payload E2E

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SRV] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)
sessions: dict[bytes, dict] = {}

def build_frame(msg_type: int, payload: bytes) -> bytes:
    body = bytes([msg_type]) + payload
    return struct.pack(">I", len(body)) + body
async def read_frame(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(4)
    n = struct.unpack(">I", hdr)[0]
    if n > MAX_FRAME:
        raise ValueError(f"frame muito grande: {n} bytes")
    return await reader.readexactly(n)

#carrega apenas uma vez
def _load_server_creds():
    with open("server_private.pem", "rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None)
    with open("server.crt", "rb") as f:
        cert_pem = f.read()
    pk_der = sk.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sk, cert_pem, pk_der


try:
    _SK_SERVER, _CERT_PEM, _PK_SERVER_DER = _load_server_creds()
    log.info("Credenciais do servidor carregadas.")
except FileNotFoundError:
    log.critical("server_private.pem / server.crt não encontrados. Execute gen_certs.py primeiro.")
    raise


# conexao cliente
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    log.info(f"Conexão de {addr}")
    cid: bytes | None = None

    try:
        #handshake
        raw = await asyncio.wait_for(read_frame(reader), timeout=10.0)
        if raw[0] != HANDSHAKE or len(raw) != 49:   # 1B tipo + 16B cid + 32B pk
            raise ValueError(f"handshake inválido (tipo={raw[0]:#x}, len={len(raw)})")
        cid    = raw[1:17] # uuid cliente
        pk_client = raw[17:49] # public key
        cid_str = cid.hex()[:16]

        log.info(f"Handshake de {cid_str}...")

        # response servidor
        salt_srv = os.urandom(16) # salt aleatorio

        # assinatura RSA-PSS(SHA-256) sobre SHA-256 cobrindo (pk_server || pk_client || client_id || salt)
        material = _PK_SERVER_DER + pk_client + cid + salt_srv
        sig = _SK_SERVER.sign(
            material,
            apd.PSS(
                mgf=apd.MGF1(hashes.SHA256()),
                salt_length=apd.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        # Payload: [4B cert_len][cert_pem][4B sig_len][sig][16B salt]
        resp = (
            struct.pack(">I", len(_CERT_PEM)) + _CERT_PEM
            + struct.pack(">I", len(sig)) + sig
            + salt_srv
        )
        writer.write(build_frame(HANDSHAKE_RESP, resp))

        # chaves de peers para novos clientes
        existing = [(eid, s["pk"], s["salt"]) for eid, s in sessions.items()]
        for eid, epk, esalt in existing:
            writer.write(build_frame(PEER_KEY, eid + epk + esalt))
        await writer.drain()

        # registrar cliente novo
        sessions[cid] = {
            "writer":   writer,
            "pk":       pk_client,
            "salt":     salt_srv,
            "seq_recv": -1,
            "seq_send": 0,
        }

        # notifica clientes existentes sobre o novo cliente
        new_peer_frame = build_frame(PEER_KEY, cid + pk_client + salt_srv)
        for eid, s in list(sessions.items()):
            if eid != cid:
                s["writer"].write(new_peer_frame)
                try:
                    await s["writer"].drain()
                except Exception as e:
                    log.warning(f"Falha ao notificar {eid.hex()[:8]}: {e}")

        log.info(f"Cliente {cid_str}... registrado. Ativos: {len(sessions)}")




        while True:
            raw = await read_frame(reader)
            msg_type = raw[0]
            payload  = raw[1:]

            if msg_type != E2E:
                log.warning(f"Tipo inesperado {msg_type:#x} de {cid_str}")
                continue

            # Frame E2E: nonce(12) + sender_id(16) + recipient_id(16) + seq_no(8) + ciphertext+tag
            if len(payload) < 68:   # 12+16+16+8+16 mínimo
                log.warning(f"Frame E2E curto de {cid_str} ({len(payload)}B)")
                continue

            sender_id    = payload[12:28]
            recipient_id = payload[28:44]
            seq_no       = struct.unpack(">Q", payload[44:52])[0]

            if sender_id != cid:
                log.warning(f"Sender ID forjado de {cid_str}")
                continue
            sess = sessions.get(cid)
            if sess is None:
                break


            # Anti-replay no servidor
            if seq_no <= sess["seq_recv"]:
                log.warning(f"Replay de {cid_str}: seq={seq_no} último={sess['seq_recv']}")
                continue
            sess["seq_recv"] = seq_no

            dest = sessions.get(recipient_id)
            if dest:
                dest["writer"].write(build_frame(E2E, payload))
                try:
                    await dest["writer"].drain()
                except Exception as e:
                    log.error(f"Erro no relay para {recipient_id.hex()[:8]}: {e}")
            else:
                log.warning(f"Destinatário {recipient_id.hex()[:8]} não conectado")

    except asyncio.TimeoutError:
        log.warning(f"Timeout no handshake de {addr}")
    except asyncio.IncompleteReadError:
        log.info(f"Desconexão de {cid.hex()[:16] if cid else addr}...")
    except Exception as e:
        log.error(f"Erro [{cid.hex()[:8] if cid else addr}]: {e}")
    finally:
        if cid and cid in sessions:
            del sessions[cid]
            log.info(f"Removido {cid.hex()[:8]}... Ativos: {len(sessions)}")
            disc = build_frame(DISCONNECT, cid)
            for s in list(sessions.values()):
                try:
                    s["writer"].write(disc)
                    asyncio.ensure_future(s["writer"].drain())
                except Exception:
                    pass
        try:
            writer.close()
        except Exception:
            pass
async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8888)
    addrs = [s.getsockname() for s in server.sockets]
    log.info(f"Escutando em {addrs}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
