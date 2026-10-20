import os, subprocess, sys
from pathlib import Path
from sqlalchemy import create_engine, inspect, text

def test_initial_migration_on_clean_sqlite(tmp_path):
    root=Path(__file__).resolve().parents[1]
    database=tmp_path/'fresh.db'
    env=os.environ.copy(); env['DATABASE_URL']='sqlite:///'+str(database); env['ENVIRONMENT']='development'
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=root,env=env,check=True,capture_output=True,text=True)
    engine=create_engine('sqlite:///'+str(database))
    names=set(inspect(engine).get_table_names())
    assert {'users','user_sessions','mfa_credentials','recovery_codes','one_time_tokens','login_events','security_alerts','audit_logs'} <= names
    assert 'alembic_version' in names
    engine.dispose()

def test_correlation_migration_backfills_old_events_without_data_loss(tmp_path):
    root=Path(__file__).resolve().parents[1]
    database=tmp_path/'upgrade.db'
    env=os.environ.copy(); env['DATABASE_URL']='sqlite:///'+str(database); env['ENVIRONMENT']='development'
    subprocess.run([sys.executable,'-m','alembic','upgrade','5935a40bb9ff'],cwd=root,env=env,check=True,capture_output=True,text=True)
    engine=create_engine('sqlite:///'+str(database))
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO login_events(user_id,email_hint,result,source,created_at) VALUES(NULL,'old***','FAILURE','127.0.0.1',CURRENT_TIMESTAMP)"))
        connection.execute(text("INSERT INTO risk_events(user_id,score,severity,decision,factors,created_at) VALUES(NULL,15,'LOW','MONITOR','one failed attempt',CURRENT_TIMESTAMP)"))
    engine.dispose()
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=root,env=env,check=True,capture_output=True,text=True)
    engine=create_engine('sqlite:///'+str(database))
    with engine.connect() as connection:
        assert connection.execute(text('SELECT count(*) FROM login_events')).scalar_one()==1
        assert connection.execute(text('SELECT correlation_id FROM login_events')).scalar_one()
        assert connection.execute(text('SELECT correlation_id FROM risk_events')).scalar_one()
    engine.dispose()
