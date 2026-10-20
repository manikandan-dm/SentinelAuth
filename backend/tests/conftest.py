import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

# Tests must not inherit a developer's or production deployment's root .env settings.
import os
os.environ['ENVIRONMENT']='development'

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from cryptography.fernet import Fernet
from app import main

@pytest.fixture
def client(monkeypatch):
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    main.Base.metadata.create_all(engine)
    monkeypatch.setattr(main,'Factory',sessionmaker(bind=engine,expire_on_commit=False))
    monkeypatch.setenv('MFA_ENCRYPTION_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('ENVIRONMENT','development')
    main.RATE.clear(); main.PREAUTH.clear()
    with TestClient(main.app) as c:
        yield c
    main.Base.metadata.drop_all(engine)
    engine.dispose()

def signup(c,email='person@example.com'):
    return c.post('/api/v1/auth/register',json={'name':'Test Person','email':email,'password':'correct-horse-battery-staple'})
def csrf(c): return {'X-CSRF-Token':c.cookies.get('sentinel_csrf') or ''}
