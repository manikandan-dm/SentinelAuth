import re
from urllib.parse import urlparse, parse_qs
from app import main

from conftest import signup, csrf

def test_registration_hash_duplicate_and_session_lifecycle(client):
    r=signup(client); assert r.status_code==201 and r.json()['name']=='Test Person'
    db=main.Factory(); user=db.query(main.User).filter_by(email='person@example.com').one()
    assert user.password_hash!='correct-horse-battery-staple' and main.ph.verify(user.password_hash,'correct-horse-battery-staple')
    session=client.post('/api/v1/auth/login',json={'email':user.email,'password':'correct-horse-battery-staple'})
    assert session.status_code==200
    row=db.query(main.UserSession).filter_by(user_id=user.id).one()
    assert row.token_hash!=client.cookies.get('sentinel_session')
    assert client.get('/api/v1/auth/me').status_code==200
    cookie=client.cookies.get('sentinel_session')
    set_cookie=' '.join(session.headers.get_list('set-cookie'))
    assert 'HttpOnly' in set_cookie and 'SameSite=lax' in set_cookie
    assert cookie and client.post('/api/v1/auth/sessions/revoke-others').status_code==403
    assert client.post('/api/v1/auth/logout',headers=csrf(client)).status_code==200
    assert client.get('/api/v1/auth/me').status_code==401
    assert signup(client).status_code==409
    db.close()

def test_csrf_verification_and_reset_tokens(client):
    signup(client)
    client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    assert client.post('/api/v1/auth/email-verification/request').status_code==403
    r=client.post('/api/v1/auth/email-verification/request',headers=csrf(client)); assert r.status_code==200
    link=r.json()['development_only_link']; token=parse_qs(urlparse(link).query)['token'][0]
    assert client.post('/api/v1/auth/email-verification/confirm',json={'token':token}).status_code==200
    assert client.post('/api/v1/auth/email-verification/confirm',json={'token':token}).status_code==400
    r=client.post('/api/v1/auth/password-reset/request',json={'email':'person@example.com'}); assert r.status_code==200
    client.post('/api/v1/auth/password-reset/request',json={'email':'person@example.com'})
    r=client.post('/api/v1/auth/password-reset/request',json={'email':'person@example.com'}); assert r.status_code==200
    token=parse_qs(urlparse(r.json()['development_only_link']).query)['token'][0]
    db=main.Factory(); assert db.query(main.SecurityAlert).filter_by(title='Repeated password-reset requests').count()==1; db.close()
    assert client.post('/api/v1/auth/password-reset/confirm',json={'token':token,'password':'a-new-safe-long-password'}).status_code==200
    assert client.get('/api/v1/auth/me').status_code==401
    assert client.post('/api/v1/auth/password-reset/confirm',json={'token':token,'password':'another-new-safe-password'}).status_code==400
    login=client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'a-new-safe-long-password'}); assert login.status_code==200

def test_mfa_enrollment_challenge_recovery_and_isolation(client):
    signup(client); client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    r=client.post('/api/v1/auth/mfa/enroll',json={'password':'correct-horse-battery-staple'},headers=csrf(client)); assert r.status_code==200
    secret=r.json()['secret']; assert r.json()['provisioning_uri'].startswith('otpauth://')
    assert client.post('/api/v1/auth/mfa/confirm',json={'code':'000000','password':'correct-horse-battery-staple'},headers=csrf(client)).status_code==400
    totp=main.pyotp.TOTP(secret).now()
    assert client.post('/api/v1/auth/mfa/confirm',json={'code':totp,'password':'correct-horse-battery-staple'},headers=csrf(client)).status_code==200
    db=main.Factory(); cred=db.query(main.MFACredential).one(); assert cred.secret_ciphertext!=secret
    # In an isolated test fixture, move the replay watermark back one step to test recovery generation.
    cred.last_totp_step=int(__import__('time').time()//30)-1; db.commit()
    generated=client.post('/api/v1/auth/mfa/recovery-codes',json={'password':'correct-horse-battery-staple','code':main.pyotp.TOTP(secret).now()},headers=csrf(client))
    assert generated.status_code==200 and len(generated.json()['codes'])==8
    codes=generated.json()['codes']; stored=db.query(main.RecoveryCode).all(); assert {main.recovery_digest(code) for code in codes}=={row.code_hash for row in stored}
    # Preserve recovery codes issued before the new HMAC-peppered storage format.
    code=codes[0]
    old_record=db.query(main.RecoveryCode).filter_by(code_hash=main.recovery_digest(code)).one()
    legacy_hash=main.digest(code.strip().upper()); old_record.code_hash=legacy_hash; db.commit()
    # Simulate a fresh browser: MFA password success must not create a session.
    client.cookies.clear()
    login=client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    assert login.status_code==200 and login.json()['mfa_required'] is True
    assert client.get('/api/v1/auth/me').status_code==401
    challenge=login.json()['challenge_id']
    # One generated recovery credential grants the challenge once.
    verify=client.post('/api/v1/auth/mfa/verify',json={'challenge_id':challenge,'code':code})
    assert verify.status_code==200 and client.get('/api/v1/auth/me').status_code==200
    assert client.post('/api/v1/auth/mfa/verify',json={'challenge_id':challenge,'code':code}).status_code==401
    db.expire_all(); assert db.query(main.RecoveryCode).filter_by(code_hash=legacy_hash).one().used is True
    db.close()

def test_admin_authorization_and_security_headers(client):
    signup(client); client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    assert client.get('/api/v1/security/summary').status_code==200
    assert client.get('/api/v1/security/events').status_code==200
    headers=client.get('/api/v1/health').headers
    assert headers['x-content-type-options']=='nosniff' and headers['content-security-policy']
    db=main.Factory(); user=db.query(main.User).first(); user.role='admin'; db.commit(); db.close()
    assert client.get('/api/v1/security/events').status_code==200
