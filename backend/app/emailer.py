"""Minimal SMTP adapter. Without SMTP config, only local development returns a dev-only link."""
import os, smtplib
from email.message import EmailMessage
from fastapi import HTTPException

def deliver(recipient:str, subject:str, body:str, dev_path:str):
    host=os.getenv('SMTP_HOST'); sender=os.getenv('SMTP_FROM')
    if host and sender:
        if not os.getenv('PUBLIC_BASE_URL'):
            raise HTTPException(503,'PUBLIC_BASE_URL must be configured for email links')
        message=EmailMessage(); message['Subject']=subject; message['From']=sender; message['To']=recipient; message.set_content(body)
        with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=10) as server:
            if os.getenv('SMTP_STARTTLS','true').lower()=='true': server.starttls()
            username=os.getenv('SMTP_USERNAME'); password=os.getenv('SMTP_PASSWORD')
            if username: server.login(username,password or '')
            server.send_message(message)
        return None
    if os.getenv('ENVIRONMENT','development')=='development': return dev_path
    raise HTTPException(503,'Email delivery is not configured')
