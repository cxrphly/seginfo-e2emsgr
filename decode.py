import struct
import sys

def decode_frame(payload_hex):
    try:
        payload = bytes.fromhex(payload_hex.strip())
    except:
        return None
    
    if len(payload) < 5:
        return None
    
    frame_len = struct.unpack(">I", payload[:4])[0]
    msg_type = payload[4]
    data = payload[5:]
    
    types = {0x01: "HANDSHAKE", 0x02: "HANDSHAKE_RESP", 
             0x03: "PEER_KEY", 0x04: "E2E", 0x05: "DISCONNECT"}
    
    result = {"type": types.get(msg_type, f"UNK({msg_type:#x})"), "len": frame_len}
    
    if msg_type == 0x01 and len(data) >= 48:
        result["client_id"] = data[:16].hex()
        result["pk_client"] = data[16:48].hex()[:32] + "..."
    
    elif msg_type == 0x03 and len(data) == 64:
        result["peer_id"] = data[:16].hex()
        result["pk_peer"] = data[16:48].hex()[:32] + "..."
        result["salt"] = data[48:64].hex()
    
    elif msg_type == 0x04 and len(data) >= 68:
        result["nonce"] = data[:12].hex()
        result["iv_base"] = data[:4].hex()
        result["seq_no"] = struct.unpack(">Q", data[44:52])[0]
        result["sender"] = data[12:28].hex()
        result["recipient"] = data[28:44].hex()
        result["ciphertext_len"] = len(data[52:])
    
    return result

for line in sys.stdin:
    parts = line.strip().split('\t')
    if len(parts) >= 6 and parts[5]:
        time = parts[0]
        src = parts[1]
        src_port = parts[2]
        dst_port = parts[3]
        payload_hex = parts[5]
        
        frame = decode_frame(payload_hex)
        if frame:
            print(f"{time:>10} {src}:{src_port} → {dst_port:5} "
                  f"{frame['type']:13} {frame['len']:4} {frame}")
