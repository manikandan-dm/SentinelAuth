from app import main
from conftest import signup,csrf

def test_login_rate_limit_and_exact_origin_cors(client):
    for _ in range(12):
        response=client.post('/api/v1/auth/login',json={'email':'unknown@example.com','password':'wrong'})
        assert response.status_code==401
    limited=client.post('/api/v1/auth/login',json={'email':'unknown@example.com','password':'wrong'})
    assert limited.status_code==429
    allowed=client.get('/api/v1/health',headers={'Origin':'http://localhost:5173'})
    denied=client.get('/api/v1/health',headers={'Origin':'https://attacker.example'})
    assert allowed.headers.get('access-control-allow-origin')=='http://localhost:5173'
    assert denied.headers.get('access-control-allow-origin') is None

def test_regular_user_cannot_change_alert_lifecycle(client):
    signup(client)
    client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    db=main.Factory(); alert=main.SecurityAlert(user_id=1,severity='HIGH',status='OPEN',title='Test security alert',description='Fixture alert',correlation_id='fixture-correlation'); db.add(alert); db.commit(); alert_id=alert.id; db.close()
    response=client.post(f'/api/v1/security/alerts/{alert_id}/acknowledge',headers=csrf(client))
    assert response.status_code==403
