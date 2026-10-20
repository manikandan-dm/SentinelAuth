from fastapi.testclient import TestClient
from sqlalchemy import select
from app import main
from conftest import signup, csrf

def test_user_data_isolation_and_session_ownership(client):
    signup(client,'one@example.com')
    c2=TestClient(main.app)
    assert signup(c2,'two@example.com').status_code==201
    client.post('/api/v1/auth/login',json={'email':'one@example.com','password':'correct-horse-battery-staple'})
    c2.post('/api/v1/auth/login',json={'email':'two@example.com','password':'correct-horse-battery-staple'})
    session_two=c2.get('/api/v1/auth/sessions').json()[0]['id']
    assert client.get('/api/v1/auth/sessions').json()[0]['id']!=session_two
    assert client.post(f'/api/v1/auth/sessions/{session_two}/revoke',headers=csrf(client)).status_code==404
    assert c2.get('/api/v1/auth/me').status_code==200
    c2.close()

def test_failed_login_alert_dedup_and_admin_lifecycle(client):
    signup(client)
    client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    for _ in range(5):
        response=client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'wrong-password'})
        assert response.status_code==401 and 'wrong-password' not in response.text
    db=main.Factory(); rows=db.scalars(select(main.SecurityAlert).where(main.SecurityAlert.user_id==1)).all()
    assert len(rows)==1 and rows[0].status=='OPEN'
    user=db.get(main.User,1); user.role='admin'; db.commit(); alert_id=rows[0].id; db.close()
    # A regular cookie is not an authorization decision; the backend reloads role on each request.
    ack=client.post(f'/api/v1/security/alerts/{alert_id}/acknowledge',headers=csrf(client))
    assert ack.status_code==200 and ack.json()['status']=='ACKNOWLEDGED'
    resolved=client.post(f'/api/v1/security/alerts/{alert_id}/resolve',headers=csrf(client))
    assert resolved.status_code==200 and resolved.json()['status']=='RESOLVED'
    assert client.post(f'/api/v1/security/alerts/{alert_id}/acknowledge',headers=csrf(client)).status_code==409

def test_expired_session_is_rejected(client):
    signup(client)
    client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    db=main.Factory(); session=db.scalar(select(main.UserSession)); from datetime import datetime,timezone,timedelta
    session.expires_at=datetime.now(timezone.utc)-timedelta(seconds=1); db.commit(); db.close()
    assert client.get('/api/v1/auth/me').status_code==401
