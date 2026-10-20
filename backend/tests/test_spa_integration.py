from pathlib import Path
import re
import pytest
from app.main import FRONTEND_INDEX
from conftest import csrf,signup

@pytest.fixture
def built_client(client):
    if not FRONTEND_INDEX.is_file(): pytest.skip('Run the frontend production build to exercise the integrated SPA route.')
    return client

def test_frontend_root_client_routes_and_assets_are_served_by_fastapi(built_client):
    root=built_client.get('/')
    assert root.status_code==200 and '<div id="root">' in root.text
    asset=re.search(r'src="([^"]+\.js)"',root.text)
    assert asset is not None
    js=built_client.get(asset.group(1))
    assert js.status_code==200 and 'javascript' in js.headers['content-type']
    for path in ['/login','/register','/dashboard','/security','/sessions','/alerts','/activity']:
        response=built_client.get(path)
        assert response.status_code==200 and '<div id="root">' in response.text
    health=built_client.get('/api/v1/health')
    assert health.status_code==200 and health.json()['status']=='ok'
    # A protected same-origin API route should be a clean auth error, not a missing-table failure.
    assert built_client.get('/api/v1/auth/me').status_code==401

def test_same_origin_registration_login_me_and_logout(built_client):
    created=signup(built_client)
    assert created.status_code==201
    login=built_client.post('/api/v1/auth/login',json={'email':'person@example.com','password':'correct-horse-battery-staple'})
    assert login.status_code==200 and built_client.get('/api/v1/auth/me').status_code==200
    assert built_client.post('/api/v1/auth/logout',headers=csrf(built_client)).status_code==200
    assert built_client.get('/api/v1/auth/me').status_code==401

def test_unknown_api_and_asset_routes_never_return_spa_html(built_client):
    api=built_client.get('/api/v1/no-such-endpoint')
    assert api.status_code==404 and api.json()=={'detail':'API route not found'}
    asset=built_client.get('/assets/not-a-real-file.js')
    assert asset.status_code==404 and '<div id="root">' not in asset.text
    missing_file=built_client.get('/non-existent.js')
    assert missing_file.status_code==404 and '<div id="root">' not in missing_file.text
    docs=built_client.get('/docs')
    assert docs.status_code==200 and 'swagger-ui' in docs.text.lower()
