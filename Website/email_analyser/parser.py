from email import message_from_bytes
from email.header import decode_header

def _decode_header_value(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out = []
    for part, enc in parts:
        if isinstance(part, bytes):
            out.append(part.decode(enc or "utf-8", errors="ignore"))
        else:
            out.append(part)
    return "".join(out)

def _extract_text_body(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                charset = part.get_content_charset() or "utf-8"
                return part.get_payload(decode=True).decode(charset, errors="ignore")
        return ""
    charset = msg.get_content_charset() or "utf-8"
    payload = msg.get_payload(decode=True)
    return payload.decode(charset, errors="ignore") if payload else ""

def parse_eml_to_dict(raw_bytes: bytes) -> dict:
    msg = message_from_bytes(raw_bytes)
    return {
        "sender":   _decode_header_value(msg.get("From")),
        "receiver": _decode_header_value(msg.get("To")),
        "subject":  _decode_header_value(msg.get("Subject")),
        "body":     _extract_text_body(msg) or "No text content found",
    }
