#!/usr/bin/env python3
"""Build the Vite client and run the integrated FastAPI app on one origin."""
from __future__ import annotations
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
BACKEND=ROOT/'backend'
FRONTEND=ROOT/'frontend'

def fail(message:str,code:int=1)->None:
    print(f'\nSentinelAuth startup error: {message}',file=sys.stderr)
    raise SystemExit(code)

def main()->None:
    if sys.version_info < (3,11):
        fail(f'Python 3.11+ is required; detected {sys.version.split()[0]}. Use Python 3.12 or 3.13 for the tested setup.')

    # Load root configuration without replacing variables already supplied by the host.
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT/'.env',override=False)
    except ImportError:
        fail('python-dotenv is missing. Install backend requirements first: python -m pip install -r backend/requirements.txt')

    try:
        import fastapi, sqlalchemy, pydantic_settings, uvicorn  # noqa: F401
    except ImportError as exc:
        fail(f'Backend dependency missing ({exc}). One-time setup: python -m pip install -r backend/requirements.txt')

    sqlalchemy_version=re.match(r"^([0-9]+)\.([0-9]+)\.([0-9]+)",sqlalchemy.__version__)
    if not sqlalchemy_version or tuple(map(int,sqlalchemy_version.groups())) < (2,0,41):
        fail(f'SQLAlchemy 2.0.41+ is required for Python 3.14 typing compatibility; detected {sqlalchemy.__version__}. Run: python -m pip install -r backend/requirements.txt')

    npm=shutil.which('npm')
    node=shutil.which('node')
    if not npm or not node:
        fail('Node.js 20.19+ and npm are required to build the frontend. Install Node.js, then retry.')
    if not (FRONTEND/'node_modules'/'vite').exists():
        fail('Frontend dependencies are not installed. One-time setup: cd frontend && npm ci')

    print('Building the React + TypeScript frontend…',flush=True)
    try:
        subprocess.run([npm,'run','build'],cwd=FRONTEND,check=True)
    except subprocess.CalledProcessError as exc:
        fail(f'Frontend build failed with exit code {exc.returncode}.')

    if not (FRONTEND/'dist'/'index.html').is_file():
        fail('Vite completed without producing frontend/dist/index.html.')

    if os.getenv('AUTO_MIGRATE','false').lower() in {'1','true','yes'}:
        print('Applying forward-only Alembic migrations…',flush=True)
        try:
            subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=BACKEND,check=True)
        except subprocess.CalledProcessError as exc:
            fail(f'Database migration failed with exit code {exc.returncode}; no destructive reset was attempted.')
    else:
        print('AUTO_MIGRATE is off. Ensure `cd backend && alembic upgrade head` has been run.',flush=True)

    # Match Alembic's working directory so relative SQLite URLs resolve to the same DB.
    os.chdir(BACKEND)
    sys.path.insert(0,str(BACKEND))
    try:
        from app.main import app
    except Exception as exc:
        fail(f'Backend application could not be loaded: {exc}')

    host=os.getenv('HOST','127.0.0.1')
    port=int(os.getenv('PORT','8000'))
    display_host='127.0.0.1' if host in {'0.0.0.0','::'} else host
    print(f'\nSentinelAuth is starting at http://{display_host}:{port}',flush=True)
    print(f'API health: http://{display_host}:{port}/api/v1/health',flush=True)
    if os.getenv('ENVIRONMENT','development')=='development':
        print(f'API docs:   http://{display_host}:{port}/docs',flush=True)
    print('Press Ctrl+C to stop. Frontend and API share this server.',flush=True)
    try:
        uvicorn.run(app,host=host,port=port,log_level=os.getenv('LOG_LEVEL','info').lower(),proxy_headers=False)
    except KeyboardInterrupt:
        print('\nSentinelAuth stopped.',flush=True)

if __name__=='__main__':
    main()
