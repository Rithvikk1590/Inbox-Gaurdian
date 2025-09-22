"""
Simple Email Analyser - Only checks for shortened URLs in body
"""

import email
from email.header import decode_header


def analyse_email_content(email_data):
    """
    Analyse email content for tinyurl.com in body only.
    
    Args:
        email_data: Dictionary with keys: sender, receiver, subject, body
        
    Returns:
        Dictionary with analysis results
    """
    results = {
        'body_highlights': [],  # List of highlights for the body
        'total_risk_points': 0
    }
    
    # Only check body for tinyurl.com
    body = email_data.get('body', '').lower()
    
    if 'tinyurl.com' in body:
        results['body_highlights'].append({
            'text': 'tinyurl.com',
            'hover_message': 'Shortened Url: +4'
        })
        results['total_risk_points'] = 4
    
    return results


def parse_eml_to_dict(email_content):
    """
    Parse .eml content into dictionary format.
    
    Args:
        email_content: Raw email content as bytes
        
    Returns:
        Dictionary with sender, receiver, subject, body
    """
    try:
        msg = email.message_from_bytes(email_content)
        
        # Extract basic fields
        email_data = {
            'sender': decode_header_simple(msg.get('From', '')),
            'receiver': decode_header_simple(msg.get('To', '')),
            'subject': decode_header_simple(msg.get('Subject', '')),
            'body': extract_body(msg)
        }
        
        return email_data
    
    except Exception as e:
        return {
            'sender': 'Error parsing',
            'receiver': 'Error parsing', 
            'subject': 'Error parsing',
            'body': f'Error parsing email: {str(e)}'
        }


def decode_header_simple(header):
    """Simple header decoder."""
    if not header:
        return ""
    
    try:
        decoded_parts = decode_header(header)
        decoded_header = ""
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                decoded_header += part.decode(encoding or 'utf-8')
            else:
                decoded_header += part
        return decoded_header
    except:
        return str(header)


def extract_body(msg):
    """Extract plain text body from email."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    charset = part.get_content_charset() or 'utf-8'
                    return part.get_payload(decode=True).decode(charset, errors='ignore')
        else:
            charset = msg.get_content_charset() or 'utf-8'
            return msg.get_payload(decode=True).decode(charset, errors='ignore')
    except:
        return "Could not extract body"
    
    return "No body content found"