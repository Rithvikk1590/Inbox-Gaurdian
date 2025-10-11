from email import message_from_bytes
from email.header import decode_header

def _decode_header_value(value: str) -> str:
    """
    Decodes an email header value into readable text.

    Handles encoded words and byte strings using their specified 
    character sets, returning a clean decoded string.
    """
    if not value:
        return ""
    # Decode header parts
    parts = decode_header(value)
    out = []
    for part, enc in parts:
        # If the header part is bytes, decode using its charset
        if isinstance(part, bytes):
            out.append(part.decode(enc or "utf-8", errors="ignore"))
        else:
            # Otherwise, append the plain text segment as-is
            out.append(part)
    # Join all decoded parts into a single string
    return "".join(out)

def _extract_text_body(msg) -> str:
    """
    Extracts the plain text content from an email message object.

    Looks through multipart messages to find 'text/plain' parts and decodes 
    them using the detected or default charset. Returns the decoded body 
    text, or an empty string if no plain text content is found.
    """
    # Check if the email has multiple MIME parts
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                # Decode using detected charset
                charset = part.get_content_charset() or "utf-8"
                return part.get_payload(decode=True).decode(charset, errors="ignore")
        # No plain text part found
        return ""
    
    # Handle single-part emails
    charset = msg.get_content_charset() or "utf-8"
    payload = msg.get_payload(decode=True)
    return payload.decode(charset, errors="ignore") if payload else ""

def _extract_attachments(msg):
    """
    Extracts and decodes attachment filenames from an email message.

    Iterates through all MIME parts, identifies attachments, decodes 
    their filenames, and returns them as a list.
    """
    attachments = []
    # Walk through all parts of the email
    for part in msg.walk():
        # Check if the current part is marked as an attachment
        if part.get_content_disposition() == "attachment":
            name = part.get_filename()
            if name:
                # Decode encoded attachment names
                attachments.append(_decode_header_value(name))
    return attachments

def parse_eml_to_dict(raw_bytes: bytes) -> dict:
    """
    Parses raw .eml file bytes into a dictionary.

    Extracts header fields, body text, and attachment filenames 
    for analysis.
    """
    # Convert the .eml file bytes into an email object
    msg = message_from_bytes(raw_bytes)
    return {
        "sender":   _decode_header_value(msg.get("From")),
        "receiver": _decode_header_value(msg.get("To")),
        "subject":  _decode_header_value(msg.get("Subject")),
        "body":     _extract_text_body(msg) or "No text content found",
        "attachments": _extract_attachments(msg),
    }
