import time
from sqlalchemy import select
from app import main
from conftest import signup, csrf

def test_totp_challenge_and_replay_rejection_with_rotation(client):
    signup(client)
    client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    before=client.get('/api/v1/auth/sessions').json()[0]['id']
    setup=client.post('/api/v1/auth/mfa/enroll',json={'password':'correct-horse-battery-staple'},headers=csrf(client))
    secret=setup.json()['secret']; code=main.pyotp.TOTP(secret).now()
    confirmed=client.post('/api/v1/auth/mfa/confirm',json={'password':'correct-horse-battery-staple','code':code},headers=csrf(client))
    assert confirmed.status_code==200
    active=client.get('/api/v1/auth/sessions').json()
    assert len(active)==1 and active[0]['id']!=before
    db=main.Factory(); old=db.get(main.UserSession,before); assert old.revoked is True
    cred=db.scalar(select(main.MFACredential)); cred.last_totp_step=int(time.time()//30)-1; db.commit()
    client.cookies.clear()
    first=client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    assert first.json()['mfa_required'] is True
    assert client.post('/api/v1/auth/mfa/verify',json={'challenge_id':first.json()['challenge_id'],'code':code}).status_code==200
    second=client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    replay=client.post('/api/v1/auth/mfa/verify',json={'challenge_id':second.json()['challenge_id'],'code':code})
    assert replay.status_code==401 and 'already used' in replay.json()['detail']
    assert db.scalar(select(main.LoginEvent).where(main.LoginEvent.result=='MFA_FAILURE')) is not None
    db.close()
