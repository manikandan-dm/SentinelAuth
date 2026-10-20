from __future__ import annotations
import os, secrets, hashlib, hmac, time, uuid
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from fastapi import FastAPI, Depends, HTTPException, Request, Response, Cookie, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings
from sqlalchemy import create_engine, String, Boolean, DateTime, Integer, Text, ForeignKey, select, func, UniqueConstraint, update
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session, relationship
from sqlalchemy.exc import IntegrityError
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
from dotenv import load_dotenv
load_dotenv()

class Settings(BaseSettings):
    database_url: str = 'sqlite:///./sentinelauth.db'
    app_secret: str = ''
    cors_origins: str = 'http://localhost:5173'
    secure_cookies: bool = False
    environment: str = 'development'
    session_hours: int = 12
settings=Settings()
if settings.environment != 'development':
    unsafe_secrets={'development-placeholder-change-to-32-random-characters','development-only-change-me-before-deploying'}
    if len(settings.app_secret)<32 or settings.app_secret in unsafe_secrets:
        raise RuntimeError('A unique APP_SECRET (32+ characters) is required outside development')
    if not settings.secure_cookies:
        raise RuntimeError('SECURE_COOKIES=true is required outside development; terminate TLS correctly first')
    from cryptography.fernet import Fernet
    try: Fernet(os.getenv('MFA_ENCRYPTION_KEY','').encode())
    except Exception as exc: raise RuntimeError('A valid MFA_ENCRYPTION_KEY is required outside development') from exc
    origins=[x.strip() for x in settings.cors_origins.split(',') if x.strip()]
    if not origins or any(not x.startswith('https://') for x in origins):
        raise RuntimeError('Production CORS_ORIGINS must contain only trusted HTTPS origins')
    if os.getenv('SMTP_HOST') and not os.getenv('PUBLIC_BASE_URL','').startswith('https://'):
        raise RuntimeError('PUBLIC_BASE_URL must be HTTPS when SMTP is configured outside development')
engine=create_engine(settings.database_url, connect_args={'check_same_thread':False} if settings.database_url.startswith('sqlite') else {}, pool_pre_ping=True)
Factory=sessionmaker(bind=engine, expire_on_commit=False)
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__='users'
    id: Mapped[int]=mapped_column(primary_key=True)
    email: Mapped[str]=mapped_column(String(320),unique=True,index=True)
    name: Mapped[str]=mapped_column(String(100),default='')
    password_hash: Mapped[str]=mapped_column(String(255))
    role: Mapped[str]=mapped_column(String(20),default='user')
    active: Mapped[bool]=mapped_column(Boolean,default=True)
    verified: Mapped[bool]=mapped_column(Boolean,default=False)
    mfa_enabled: Mapped[bool]=mapped_column(Boolean,default=False)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class UserSession(Base):
    __tablename__='user_sessions'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    token_hash: Mapped[str]=mapped_column(String(64),unique=True,index=True)
    csrf_hash: Mapped[str]=mapped_column(String(64))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    last_activity: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
    revoked: Mapped[bool]=mapped_column(Boolean,default=False)
    user_agent: Mapped[str]=mapped_column(String(300),default='')
class LoginEvent(Base):
    __tablename__='login_events'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'),nullable=True,index=True)
    email_hint: Mapped[str]=mapped_column(String(120),default='')
    result: Mapped[str]=mapped_column(String(30),index=True)
    correlation_id: Mapped[str]=mapped_column(String(36),default=lambda:str(uuid.uuid4()),index=True)
    source: Mapped[str]=mapped_column(String(80),default='')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)
class RiskEvent(Base):
    __tablename__='risk_events'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'),nullable=True,index=True)
    score: Mapped[int]=mapped_column(Integer)
    severity: Mapped[str]=mapped_column(String(20))
    decision: Mapped[str]=mapped_column(String(30))
    factors: Mapped[str]=mapped_column(Text)
    correlation_id: Mapped[str]=mapped_column(String(36),default=lambda:str(uuid.uuid4()),index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)
class SecurityAlert(Base):
    __tablename__='security_alerts'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'),nullable=True,index=True)
    severity: Mapped[str]=mapped_column(String(20),index=True)
    status: Mapped[str]=mapped_column(String(20),default='OPEN',index=True)
    title: Mapped[str]=mapped_column(String(160))
    description: Mapped[str]=mapped_column(String(500))
    correlation_id: Mapped[str]=mapped_column(String(36),unique=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)
    changed_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
class AuditLog(Base):
    __tablename__='audit_logs'
    id: Mapped[int]=mapped_column(primary_key=True)
    actor_id: Mapped[int|None]=mapped_column(ForeignKey('users.id'),nullable=True)
    action: Mapped[str]=mapped_column(String(80))
    resource: Mapped[str]=mapped_column(String(100))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc))
class MFACredential(Base):
    __tablename__='mfa_credentials'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),unique=True)
    secret_ciphertext: Mapped[str]=mapped_column(Text)
    last_totp_step: Mapped[int|None]=mapped_column(Integer,nullable=True)
class OneTimeToken(Base):
    __tablename__='one_time_tokens'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    purpose: Mapped[str]=mapped_column(String(30),index=True)
    token_hash: Mapped[str]=mapped_column(String(64),unique=True,index=True)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),index=True)
    used: Mapped[bool]=mapped_column(Boolean,default=False)
class RecoveryCode(Base):
    __tablename__='recovery_codes'
    id: Mapped[int]=mapped_column(primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey('users.id',ondelete='CASCADE'),index=True)
    code_hash: Mapped[str]=mapped_column(String(64),index=True)
    used: Mapped[bool]=mapped_column(Boolean,default=False)

# Migrations own schema creation. Local startup only works after `alembic upgrade head`.
ph=PasswordHasher(time_cost=2,memory_cost=19456,parallelism=1)
app=FastAPI(title='SentinelAuth API',version='1.0.0',docs_url='/docs' if settings.environment=='development' else None,redoc_url=None,openapi_url='/openapi.json' if settings.environment=='development' else None)
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(',') if x.strip()],allow_credentials=True,allow_methods=['GET','POST','PATCH','DELETE','OPTIONS'],allow_headers=['Content-Type','X-CSRF-Token'])
@app.middleware('http')
async def secure_headers(request:Request, call_next):
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','Permissions-Policy':'camera=(), microphone=(), geolocation=()'})
    if settings.environment=='development':
        response.headers['Content-Security-Policy']="default-src 'self'; base-uri 'self'; object-src 'none'"
        # Development preview hosts embed the app in a browser frame; enforce frame denial in production.
        if request.url.path=='/docs': response.headers['Content-Security-Policy']="default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; object-src 'none'"
    else:
        response.headers['X-Frame-Options']='DENY'
        response.headers['Content-Security-Policy']="default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    if settings.secure_cookies: response.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    return response

def dbdep():
    db=Factory()
    try: yield db
    finally: db.close()
def digest(raw:str)->str: return hashlib.sha256(raw.encode()).hexdigest()
def recovery_digest(code:str)->str:
    # Recovery codes have less entropy than session/reset tokens; use the application pepper.
    key=settings.app_secret.encode() if settings.app_secret else b'sentinelauth-development-only-pepper'
    return hmac.new(key,code.strip().upper().encode(),hashlib.sha256).hexdigest()
def new_session(db:Session,user:User,request:Request,response:Response):
    raw=secrets.token_urlsafe(40); csrf=secrets.token_urlsafe(32)
    row=UserSession(user_id=user.id,token_hash=digest(raw),csrf_hash=digest(csrf),expires_at=datetime.now(timezone.utc)+timedelta(hours=settings.session_hours),user_agent=request.headers.get('user-agent','')[:300])
    db.add(row); db.commit()
    response.set_cookie('sentinel_session',raw,httponly=True,secure=settings.secure_cookies,samesite='lax',max_age=settings.session_hours*3600,path='/')
    response.set_cookie('sentinel_csrf',csrf,httponly=False,secure=settings.secure_cookies,samesite='lax',max_age=settings.session_hours*3600,path='/')
    return row
def current(request:Request,db:Session=Depends(dbdep),token:str|None=Cookie(None,alias='sentinel_session')):
    if not token: raise HTTPException(401,'Authentication required')
    row=db.scalar(select(UserSession).where(UserSession.token_hash==digest(token),UserSession.revoked==False,UserSession.expires_at>datetime.now(timezone.utc)))
    if not row: raise HTTPException(401,'Session expired')
    user=db.get(User,row.user_id)
    if not user or not user.active: raise HTTPException(401,'Authentication required')
    if datetime.now(timezone.utc)-row.last_activity.replace(tzinfo=timezone.utc)>timedelta(minutes=30): row.revoked=True; db.commit(); raise HTTPException(401,'Session idle timeout')
    row.last_activity=datetime.now(timezone.utc); db.commit()
    return user,row

def csrf_check(request:Request, pair=Depends(current), csrf_cookie:str|None=Cookie(None,alias='sentinel_csrf')):
    user,row=pair
    if not csrf_cookie or request.headers.get('x-csrf-token')!=csrf_cookie or digest(csrf_cookie)!=row.csrf_hash: raise HTTPException(403,'CSRF validation failed')
    return pair
class Register(BaseModel): name:str=Field(min_length=1,max_length=100); email:EmailStr; password:str=Field(min_length=12,max_length=128)
class Login(BaseModel): email:EmailStr; password:str=Field(min_length=1,max_length=128)
class LoginCode(BaseModel): challenge_id:str; code:str=Field(min_length=6,max_length=64)
class CodeInput(BaseModel): code:str=Field(min_length=6,max_length=64)
class MFAProof(BaseModel): password:str=Field(min_length=1,max_length=128); code:str=Field(min_length=6,max_length=64)
class TokenInput(BaseModel): token:str=Field(min_length=20,max_length=200)
class ResetInput(BaseModel): token:str=Field(min_length=20,max_length=200); password:str=Field(min_length=12,max_length=128)
class Proof(BaseModel): password:str=Field(min_length=1,max_length=128); code:str|None=None
class ProfileInput(BaseModel): name:str=Field(min_length=1,max_length=100)
class EmailRequest(BaseModel): email:EmailStr
class Challenge(BaseModel): challenge_id:str; code:str
class AlertStatus(BaseModel):
    @classmethod
    def validate(cls): return cls()
RATE=defaultdict(deque)
def limited(key:str,limit=10,seconds=60):
    now=time.time(); q=RATE[key]
    while q and q[0]<now-seconds: q.popleft()
    if len(q)>=limit: raise HTTPException(429,'Too many requests; try again later')
    q.append(now)
PREAUTH={}

def issue_token(db:Session,user:User,purpose:str,ttl:int):
    raw=secrets.token_urlsafe(36); db.add(OneTimeToken(user_id=user.id,purpose=purpose,token_hash=digest(raw),expires_at=datetime.now(timezone.utc)+timedelta(seconds=ttl))); db.commit(); return raw

def consume_token(db:Session,raw:str,purpose:str):
    row=db.scalar(select(OneTimeToken).where(OneTimeToken.token_hash==digest(raw),OneTimeToken.purpose==purpose,OneTimeToken.used==False,OneTimeToken.expires_at>datetime.now(timezone.utc)))
    if not row: raise HTTPException(400,'Invalid or expired token')
    user_id=row.user_id
    claimed=db.execute(update(OneTimeToken).where(OneTimeToken.id==row.id,OneTimeToken.used==False,OneTimeToken.expires_at>datetime.now(timezone.utc)).values(used=True).execution_options(synchronize_session=False))
    if claimed.rowcount!=1: raise HTTPException(400,'Invalid or expired token')
    row.used=True
    return db.get(User,user_id)

@app.post('/api/v1/auth/email-verification/request')
def request_verification(request:Request, pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    user,_=pair; limited('verify:'+str(user.id),3,3600)
    if user.verified: return {'message':'Email is already verified'}
    raw=issue_token(db,user,'verify',3600); from app.emailer import deliver
    path='/verify-email?token='+raw
    link=os.getenv('PUBLIC_BASE_URL','').rstrip('/')+path if os.getenv('PUBLIC_BASE_URL') else path
    development_link=deliver(user.email,'Verify your SentinelAuth email',f'Open {link} to verify your email.',path)
    result={'message':'If delivery is configured, a verification email has been sent.'}
    if development_link: result['development_only_link']=development_link
    return result

@app.post('/api/v1/auth/email-verification/confirm')
def confirm_verification(data:TokenInput,db:Session=Depends(dbdep)):
    user=consume_token(db,data.token,'verify'); user.verified=True; db.commit(); return {'verified':True}

@app.post('/api/v1/auth/password-reset/request')
def request_password_reset(data:EmailRequest,request:Request,db:Session=Depends(dbdep)):
    normalized=str(data.email).lower().strip(); limited('reset:'+normalized,3,3600)
    generic={'message':'Request received. If the account exists and email delivery succeeds, instructions will arrive.'}
    if settings.environment!='development' and not (os.getenv('SMTP_HOST') and os.getenv('SMTP_FROM')):
        raise HTTPException(503,'Password-reset email delivery is not configured')
    user=db.scalar(select(User).where(User.email==normalized))
    if not user: return generic
    raw=issue_token(db,user,'reset',1800); from app.emailer import deliver
    db.add(AuditLog(actor_id=user.id,action='password_reset.requested',resource='password_reset')); db.flush()
    requests=db.scalar(select(func.count(AuditLog.id)).where(AuditLog.actor_id==user.id,AuditLog.action=='password_reset.requested',AuditLog.created_at>datetime.now(timezone.utc)-timedelta(hours=1))) or 0
    if requests>=3 and not db.scalar(select(SecurityAlert.id).where(SecurityAlert.user_id==user.id,SecurityAlert.status=='OPEN',SecurityAlert.title=='Repeated password-reset requests')): db.add(SecurityAlert(user_id=user.id,severity='MEDIUM',title='Repeated password-reset requests',description='Multiple password-reset requests were received within one hour. If unexpected, review account activity.',correlation_id=str(uuid.uuid4())))
    db.commit()
    path='/reset-password?token='+raw
    link=os.getenv('PUBLIC_BASE_URL','').rstrip('/')+path if os.getenv('PUBLIC_BASE_URL') else path
    try: dev_link=deliver(user.email,'Reset your SentinelAuth password',f'Open {link} to reset your password.',path)
    except HTTPException: return generic
    result=generic
    if dev_link: result={**generic,'development_only_link':dev_link}
    return result

@app.post('/api/v1/auth/password-reset/confirm')
def confirm_password_reset(data:ResetInput,db:Session=Depends(dbdep)):
    user=consume_token(db,data.token,'reset'); user.password_hash=ph.hash(data.password)
    for session in db.scalars(select(UserSession).where(UserSession.user_id==user.id,UserSession.revoked==False)).all(): session.revoked=True
    db.add(AuditLog(actor_id=user.id,action='account.password_reset',resource='user')); db.commit(); return {'ok':True}

@app.patch('/api/v1/auth/profile')
def update_profile(data:ProfileInput,pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    user,_=pair; user.name=data.name.strip(); db.add(AuditLog(actor_id=user.id,action='profile.updated',resource='user')); db.commit(); return {'id':user.id,'name':user.name,'email':user.email}

@app.post('/api/v1/auth/mfa/recovery-codes')
def generate_recovery_codes(data:Proof,request:Request,pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    user,_=pair; ip=request.client.host if request.client else 'unknown'
    try: valid=ph.verify(user.password_hash,data.password)
    except VerifyMismatchError: valid=False
    if not valid or not user.mfa_enabled: raise HTTPException(401,'Reauthentication failed')
    cred=db.scalar(select(MFACredential).where(MFACredential.user_id==user.id))
    if not cred: raise HTTPException(401,'Reauthentication failed')
    if data.code:
        totp=pyotp.TOTP(decrypt_secret(cred.secret_ciphertext))
        if not totp.verify(data.code,valid_window=0): log_mfa_failure(db,user,ip); raise HTTPException(401,'Invalid authentication code')
        step=int(time.time()//totp.interval)
        if cred.last_totp_step is not None and step<=cred.last_totp_step:
            log_mfa_failure(db,user,ip); raise HTTPException(401,'Authentication code already used')
        cred.last_totp_step=step
    else: raise HTTPException(422,'Authenticator code is required')
    for row in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id==user.id)).all(): db.delete(row)
    codes=[secrets.token_hex(8).upper() for _ in range(8)]
    db.add_all([RecoveryCode(user_id=user.id,code_hash=recovery_digest(c)) for c in codes]); db.add(AuditLog(actor_id=user.id,action='mfa.recovery_codes_regenerated',resource='user')); db.commit()
    return {'codes':codes,'warning':'Shown once. Save securely; prior codes are invalidated.'}

@app.get('/api/v1/health')
def health(): return {'status':'ok','service':'sentinelauth'}
@app.post('/api/v1/auth/register',status_code=201)
def register(payload:Register,request:Request,db:Session=Depends(dbdep)):
    email=str(payload.email).lower().strip(); limited('register:'+email,5,3600)
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,'Unable to create account with those details')
    user=User(email=email,name=payload.name.strip(),password_hash=ph.hash(payload.password)); db.add(user)
    try:
        db.flush(); db.add(AuditLog(actor_id=user.id,action='account.registered',resource='user')); db.commit()
    except IntegrityError:
        db.rollback(); raise HTTPException(409,'Unable to create account with those details')
    raw=issue_token(db,user,'verify',3600); from app.emailer import deliver
    result={'id':user.id,'email':user.email,'name':user.name,'verified':user.verified,'message':'Account created.'}
    try:
        path='/verify-email?token='+raw; link=os.getenv('PUBLIC_BASE_URL','').rstrip('/')+path if os.getenv('PUBLIC_BASE_URL') else path
        dev_link=deliver(user.email,'Verify your SentinelAuth email',f'Open {link} to verify.',path)
        result['message']='Account created. Check email for verification.'
        if dev_link: result['development_only_link']=dev_link
    except HTTPException:
        result['message']='Account created, but email delivery is unavailable. Configure SMTP and request verification again.'
    return result
@app.post('/api/v1/auth/login')
def login(payload:Login,request:Request,response:Response,db:Session=Depends(dbdep)):
    email=str(payload.email).lower().strip(); ip=request.client.host if request.client else 'unknown'; limited('login:'+ip,12,60)
    user=db.scalar(select(User).where(User.email==email)); valid=False
    if user:
        try: valid=ph.verify(user.password_hash,payload.password)
        except VerifyMismatchError: valid=False
    correlation=str(uuid.uuid4()); event=LoginEvent(user_id=user.id if user else None,email_hint=email[:3]+'***',result='SUCCESS' if valid else 'FAILURE',correlation_id=correlation,source=ip[:80]); db.add(event)
    failure_query=select(func.count(LoginEvent.id)).where(LoginEvent.source==ip,LoginEvent.result.in_(['FAILURE','MFA_FAILURE']),LoginEvent.created_at>datetime.now(timezone.utc)-timedelta(minutes=10))
    failure_query=failure_query.where(LoginEvent.user_id==user.id) if user else failure_query.where(LoginEvent.user_id.is_(None))
    failures=db.scalar(failure_query) or 0
    score=min(100,failures*15); sev='CRITICAL' if score>=80 else 'HIGH' if score>=60 else 'MEDIUM' if score>=30 else 'LOW'; decision='BLOCK' if score>=80 else 'MONITOR' if score>=30 else 'ALLOW'
    db.add(RiskEvent(user_id=user.id if user else None,score=score,severity=sev,decision=decision,factors=f'{failures} recent failed attempts from source',correlation_id=correlation))
    if not valid:
        if score>=60 and not db.scalar(select(SecurityAlert.id).where(SecurityAlert.user_id== (user.id if user else None),SecurityAlert.status=='OPEN',SecurityAlert.title=='Repeated failed sign-in attempts')): db.add(SecurityAlert(user_id=user.id if user else None,severity=sev,title='Repeated failed sign-in attempts',description=f'{failures} recent failures observed. Automated IP geolocation is not configured.',correlation_id=correlation))
        db.commit(); raise HTTPException(401,'Invalid email or password')
    if score>=80 or (score>=60 and not user.mfa_enabled):
        event.result='BLOCKED_RISK'; db.commit(); raise HTTPException(401,'Invalid email or password')
    if not user.active: db.commit(); raise HTTPException(403,'Account unavailable')
    if user.mfa_enabled:
        event.result='MFA_REQUIRED'
        challenge=secrets.token_urlsafe(32); PREAUTH[digest(challenge)]=(user.id,time.time()+300)
        db.commit(); return {'mfa_required':True,'challenge_id':challenge}
    new_session(db,user,request,response); db.commit()
    return {'mfa_required':False,'user':{'id':user.id,'email':user.email,'name':user.name,'role':user.role,'verified':user.verified,'mfa_enabled':user.mfa_enabled}}
def log_mfa_failure(db:Session,user:User,ip:str):
    correlation=str(uuid.uuid4()); db.add(LoginEvent(user_id=user.id,email_hint=user.email[:3]+'***',result='MFA_FAILURE',correlation_id=correlation,source=ip[:80])); db.flush()
    failures=db.scalar(select(func.count(LoginEvent.id)).where(LoginEvent.user_id==user.id,LoginEvent.source==ip,LoginEvent.result.in_(['FAILURE','MFA_FAILURE']),LoginEvent.created_at>datetime.now(timezone.utc)-timedelta(minutes=10))) or 0
    score=min(100,failures*20); severity='CRITICAL' if score>=80 else 'HIGH' if score>=60 else 'MEDIUM' if score>=30 else 'LOW'; decision='BLOCK' if score>=80 else 'STEP_UP_AUTH' if score>=60 else 'MONITOR' if score>=30 else 'ALLOW'
    db.add(RiskEvent(user_id=user.id,score=score,severity=severity,decision=decision,factors=f'{failures} recent authentication-factor failures',correlation_id=correlation))
    existing=db.scalar(select(SecurityAlert.id).where(SecurityAlert.user_id==user.id,SecurityAlert.status=='OPEN',SecurityAlert.title=='Repeated MFA failures'))
    if score>=60 and not existing: db.add(SecurityAlert(user_id=user.id,severity=severity,title='Repeated MFA failures',description=f'{failures} recent MFA failures observed from the same source.',correlation_id=correlation))
    db.commit()

@app.post('/api/v1/auth/mfa/verify')
def mfa_verify(data:Challenge,request:Request,response:Response,db:Session=Depends(dbdep)):
    ip=request.client.host if request.client else 'unknown'; limited('mfa:'+ip,8,60)
    entry=PREAUTH.pop(digest(data.challenge_id),None)
    if not entry or entry[1]<time.time(): raise HTTPException(401,'Challenge expired')
    user=db.get(User,entry[0]); cred=db.scalar(select(MFACredential).where(MFACredential.user_id==user.id)) if user else None
    if not cred:
        if user: log_mfa_failure(db,user,ip)
        raise HTTPException(401,'Invalid authentication code')
    secret=decrypt_secret(cred.secret_ciphertext); totp=pyotp.TOTP(secret); matched=totp.verify(data.code,valid_window=0)
    if matched:
        step=int(time.time()//totp.interval)
        if cred.last_totp_step is not None and step<=cred.last_totp_step:
            log_mfa_failure(db,user,ip); raise HTTPException(401,'Authentication code already used')
        cred.last_totp_step=step
    else:
        recovery=db.scalar(select(RecoveryCode).where(RecoveryCode.user_id==user.id,RecoveryCode.code_hash.in_([recovery_digest(data.code),digest(data.code.strip().upper())]),RecoveryCode.used==False))
        if not recovery:
            log_mfa_failure(db,user,ip); raise HTTPException(401,'Invalid authentication code')
        claimed=db.execute(update(RecoveryCode).where(RecoveryCode.id==recovery.id,RecoveryCode.used==False).values(used=True).execution_options(synchronize_session=False))
        if claimed.rowcount!=1: raise HTTPException(401,'Invalid authentication code')
        recovery.used=True
    db.add(LoginEvent(user_id=user.id,email_hint=user.email[:3]+'***',result='SUCCESS',source=ip[:80])); new_session(db,user,request,response); db.commit(); return {'user':{'id':user.id,'email':user.email,'name':user.name,'role':user.role,'verified':user.verified,'mfa_enabled':True}}
@app.get('/api/v1/auth/me')
def me(pair=Depends(current)):
    u,_=pair; return {'id':u.id,'email':u.email,'name':u.name,'role':u.role,'verified':u.verified,'mfa_enabled':u.mfa_enabled}
@app.post('/api/v1/auth/logout')
def logout(response:Response,pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    u,s=pair; s.revoked=True; db.add(AuditLog(actor_id=u.id,action='session.logout',resource=f'session:{s.id}')); db.commit(); response.delete_cookie('sentinel_session',path='/'); response.delete_cookie('sentinel_csrf',path='/'); return {'ok':True}
@app.get('/api/v1/auth/sessions')
def sessions(pair=Depends(current),db:Session=Depends(dbdep)):
    u,_=pair; rows=db.scalars(select(UserSession).where(UserSession.user_id==u.id,UserSession.revoked==False,UserSession.expires_at>datetime.now(timezone.utc))).all()
    return [{'id':x.id,'created_at':x.created_at,'expires_at':x.expires_at,'user_agent':x.user_agent} for x in rows]
@app.post('/api/v1/auth/sessions/{session_id}/revoke')
def revoke(session_id:str,pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    u,_=pair; s=db.scalar(select(UserSession).where(UserSession.id==session_id,UserSession.user_id==u.id,UserSession.revoked==False))
    if not s: raise HTTPException(404,'Session not found')
    s.revoked=True; db.add(AuditLog(actor_id=u.id,action='session.revoked',resource=f'session:{s.id}')); db.commit(); return {'ok':True}
@app.post('/api/v1/auth/sessions/revoke-others')
def revoke_others(pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    u,current_session=pair
    for s in db.scalars(select(UserSession).where(UserSession.user_id==u.id,UserSession.revoked==False)).all():
        if s.id!=current_session.id:
            s.revoked=True; db.add(AuditLog(actor_id=u.id,action='session.revoked_other',resource=f'session:{s.id}'))
    db.commit(); return {'ok':True}

def encrypt_secret(secret:str)->str:
    key=os.getenv('MFA_ENCRYPTION_KEY','')
    if len(key)<32: raise HTTPException(503,'MFA encryption is not configured; set MFA_ENCRYPTION_KEY')
    from cryptography.fernet import Fernet
    try: return Fernet(key.encode()).encrypt(secret.encode()).decode()
    except Exception: raise HTTPException(503,'MFA encryption key must be a valid Fernet key')
def decrypt_secret(value:str)->str:
    from cryptography.fernet import Fernet
    return Fernet(os.environ['MFA_ENCRYPTION_KEY'].encode()).decrypt(value.encode()).decode()
@app.post('/api/v1/auth/mfa/enroll')
def mfa_enroll(data:Proof,pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    u,_=pair
    try: valid_password=ph.verify(u.password_hash,data.password)
    except VerifyMismatchError: valid_password=False
    if not valid_password: raise HTTPException(401,'Reauthentication failed')
    if u.mfa_enabled: raise HTTPException(409,'MFA is already enabled')
    secret=pyotp.random_base32(); ciphertext=encrypt_secret(secret)
    old=db.scalar(select(MFACredential).where(MFACredential.user_id==u.id))
    if old: db.delete(old)
    db.add(MFACredential(user_id=u.id,secret_ciphertext=ciphertext)); db.commit()
    return {'secret':secret,'provisioning_uri':pyotp.TOTP(secret).provisioning_uri(name=u.email,issuer_name='SentinelAuth')}
@app.post('/api/v1/auth/mfa/confirm')
def mfa_confirm(data:MFAProof,request:Request,response:Response,pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    u,_=pair; cred=db.scalar(select(MFACredential).where(MFACredential.user_id==u.id))
    try: valid_password=ph.verify(u.password_hash,data.password)
    except VerifyMismatchError: valid_password=False
    if not valid_password or not cred or not pyotp.TOTP(decrypt_secret(cred.secret_ciphertext)).verify(data.code,valid_window=0): raise HTTPException(400,'Invalid code or password; enrollment remains inactive')
    u.mfa_enabled=True; totp=pyotp.TOTP(decrypt_secret(cred.secret_ciphertext)); cred.last_totp_step=int(time.time()//totp.interval); db.add(AuditLog(actor_id=u.id,action='mfa.enabled',resource='user')); current_session=pair[1]; current_session.revoked=True; db.flush(); new_session(db,u,request,response); return {'enabled':True}
@app.post('/api/v1/auth/mfa/disable')
def mfa_disable(data:Proof,request:Request,response:Response,pair=Depends(csrf_check),db:Session=Depends(dbdep)):
    u,_=pair; cred=db.scalar(select(MFACredential).where(MFACredential.user_id==u.id))
    try: valid_password=ph.verify(u.password_hash,data.password)
    except VerifyMismatchError: valid_password=False
    if not cred or not valid_password or not data.code: raise HTTPException(401,'Reauthentication failed')
    totp=pyotp.TOTP(decrypt_secret(cred.secret_ciphertext))
    if not totp.verify(data.code,valid_window=0): raise HTTPException(401,'Reauthentication failed')
    step=int(time.time()//totp.interval)
    if cred.last_totp_step is not None and step<=cred.last_totp_step: raise HTTPException(401,'Authentication code already used')
    u.mfa_enabled=False; db.delete(cred); db.add(AuditLog(actor_id=u.id,action='mfa.disabled',resource='user'))
    for r in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id==u.id)).all(): db.delete(r)
    current_session=pair[1]; current_session.revoked=True; db.flush(); new_session(db,u,request,response); return {'enabled':False}

def admin(pair):
    u,_=pair
    if u.role!='admin': raise HTTPException(403,'Administrator access required')
@app.get('/api/v1/security/summary')
def summary(pair=Depends(current),db:Session=Depends(dbdep)):
    u,_=pair
    own= u.role!='admin'
    alerts=db.scalars(select(SecurityAlert).where(SecurityAlert.user_id==u.id) if own else select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(8)).all()
    event_q=select(func.count(LoginEvent.id)).where(LoginEvent.user_id==u.id) if own else select(func.count(LoginEvent.id))
    open_q=select(func.count(SecurityAlert.id)).where(SecurityAlert.status=='OPEN',SecurityAlert.user_id==u.id) if own else select(func.count(SecurityAlert.id)).where(SecurityAlert.status=='OPEN')
    risk_q=select(func.avg(RiskEvent.score)).where(RiskEvent.user_id==u.id) if own else select(func.avg(RiskEvent.score))
    sessions_q=select(func.count(UserSession.id)).where(UserSession.user_id==u.id,UserSession.revoked==False,UserSession.expires_at>datetime.now(timezone.utc)) if own else select(func.count(UserSession.id)).where(UserSession.revoked==False,UserSession.expires_at>datetime.now(timezone.utc))
    return {'events':db.scalar(event_q) or 0,'open_alerts':db.scalar(open_q) or 0,'risk':db.scalar(risk_q) or 0,'active_sessions':db.scalar(sessions_q) or 0,'recent_alerts':[alert_json(a) for a in alerts]}
def alert_json(a): return {'id':a.id,'severity':a.severity,'status':a.status,'title':a.title,'description':a.description,'created_at':a.created_at,'correlation_id':a.correlation_id}
@app.get('/api/v1/security/risk-summary')
def risk_summary(pair=Depends(current),db:Session=Depends(dbdep)):
    u,_=pair; scope=() if u.role=='admin' else (RiskEvent.user_id==u.id,); bands={s:db.scalar(select(func.count(RiskEvent.id)).where(RiskEvent.severity==s,*scope)) or 0 for s in ['LOW','MEDIUM','HIGH','CRITICAL']}; recs=[]
    if not u.mfa_enabled: recs.append('Enable TOTP multi-factor authentication to add a second factor.')
    if bands['HIGH']+bands['CRITICAL']: recs.append('Review recent authentication alerts and revoke sessions you do not recognize.')
    if not recs: recs.append('Keep MFA enabled and review active sessions periodically.')
    recent=db.scalars(select(RiskEvent).where(*scope).order_by(RiskEvent.created_at.desc()).limit(20)).all()
    return {'average_score':round(db.scalar(select(func.avg(RiskEvent.score)).where(*scope)) or 0,1),'total':db.scalar(select(func.count(RiskEvent.id)).where(*scope)) or 0,'bands':bands,'recommendations':recs,'recent':[{'score':e.score,'severity':e.severity,'decision':e.decision,'factors':e.factors,'correlation_id':e.correlation_id,'created_at':e.created_at} for e in recent],'policy':'Score counts recent authentication-factor failures from the observed source; deterministic heuristic, not trained AI.'}
@app.get('/api/v1/security/alerts')
def alerts(status:str|None=None,severity:str|None=None,limit:int=Query(default=50,ge=1,le=100),offset:int=Query(default=0,ge=0),pair=Depends(current),db:Session=Depends(dbdep)):
    u,_=pair; q=select(SecurityAlert) if u.role=='admin' else select(SecurityAlert).where(SecurityAlert.user_id==u.id)
    if status:
        if status not in ['OPEN','ACKNOWLEDGED','RESOLVED']: raise HTTPException(400,'Invalid status')
        q=q.where(SecurityAlert.status==status)
    if severity:
        if severity not in ['LOW','MEDIUM','HIGH','CRITICAL']: raise HTTPException(400,'Invalid severity')
        q=q.where(SecurityAlert.severity==severity)
    rows=db.scalars(q.order_by(SecurityAlert.created_at.desc()).offset(offset).limit(limit)).all(); return {'items':[alert_json(a) for a in rows],'limit':limit,'offset':offset}
@app.get('/api/v1/security/alerts/{alert_id}')
def alert_detail(alert_id:int,pair=Depends(current),db:Session=Depends(dbdep)):
    u,_=pair; a=db.get(SecurityAlert,alert_id)
    if not a or (u.role!='admin' and a.user_id!=u.id): raise HTTPException(404,'Alert not found')
    return alert_json(a)
def change_alert(alert_id:int,status:str,pair,db:Session):
    admin(pair)
    allowed=['OPEN','ACKNOWLEDGED','RESOLVED'] if status=='RESOLVED' else ['OPEN','ACKNOWLEDGED']
    result=db.execute(update(SecurityAlert).where(SecurityAlert.id==alert_id,SecurityAlert.status.in_(allowed)).values(status=status,changed_at=datetime.now(timezone.utc)).execution_options(synchronize_session=False))
    if result.rowcount!=1:
        a=db.get(SecurityAlert,alert_id)
        if not a: raise HTTPException(404,'Alert not found')
        raise HTTPException(409,'Resolved alerts cannot be reopened')
    db.add(AuditLog(actor_id=pair[0].id,action='alert.'+status.lower(),resource=f'alert:{alert_id}')); db.commit()
    a=db.scalar(select(SecurityAlert).where(SecurityAlert.id==alert_id).execution_options(populate_existing=True)); return alert_json(a)
@app.post('/api/v1/security/alerts/{alert_id}/acknowledge')
def acknowledge(alert_id:int,pair=Depends(csrf_check),db:Session=Depends(dbdep)): return change_alert(alert_id,'ACKNOWLEDGED',pair,db)
@app.post('/api/v1/security/alerts/{alert_id}/resolve')
def resolve(alert_id:int,pair=Depends(csrf_check),db:Session=Depends(dbdep)): return change_alert(alert_id,'RESOLVED',pair,db)
@app.get('/api/v1/security/events')
def events(limit:int=Query(default=50,ge=1,le=100),offset:int=Query(default=0,ge=0),pair=Depends(current),db:Session=Depends(dbdep)):
    u,_=pair; q=select(LoginEvent) if u.role=='admin' else select(LoginEvent).where(LoginEvent.user_id==u.id); rows=db.scalars(q.order_by(LoginEvent.created_at.desc()).offset(offset).limit(limit)).all()
    return {'items':[{'id':x.id,'result':x.result,'correlation_id':x.correlation_id,'email_hint':x.email_hint,'source':x.source,'created_at':x.created_at} for x in rows],'limit':limit,'offset':offset}
@app.exception_handler(Exception)
async def safe_error(request,exc):
    if isinstance(exc,HTTPException): return JSONResponse(status_code=exc.status_code,content={'detail':exc.detail},headers=exc.headers)
    return JSONResponse(status_code=500,content={'detail':'Internal server error'})

# Serve the production Vite build from the same FastAPI origin. Only the Vite asset
# directory is mounted; dotfiles, databases, source, and environment files are never exposed.
PROJECT_ROOT=Path(os.getenv('SENTINELAUTH_PROJECT_ROOT',str(Path(__file__).resolve().parents[2])))
FRONTEND_DIST=PROJECT_ROOT/'frontend'/'dist'
FRONTEND_INDEX=FRONTEND_DIST/'index.html'
if (FRONTEND_DIST/'assets').is_dir():
    app.mount('/assets',StaticFiles(directory=str(FRONTEND_DIST/'assets'),check_dir=True),name='frontend-assets')

@app.get('/',include_in_schema=False)
def frontend_root():
    if not FRONTEND_INDEX.is_file(): return JSONResponse(status_code=503,content={'detail':'Frontend build is unavailable. Run python run.py to build and start the integrated application.'})
    return FileResponse(FRONTEND_INDEX,media_type='text/html')

@app.get('/{spa_path:path}',include_in_schema=False)
def frontend_routes(spa_path:str):
    normalized=spa_path.lstrip('/')
    if normalized=='api' or normalized.startswith('api/'):
        return JSONResponse(status_code=404,content={'detail':'API route not found'})
    if normalized=='assets' or normalized.startswith('assets/'):
        return JSONResponse(status_code=404,content={'detail':'Static asset not found'})
    if Path(normalized).suffix:
        return JSONResponse(status_code=404,content={'detail':'Static file not found'})
    if not FRONTEND_INDEX.is_file():
        return JSONResponse(status_code=503,content={'detail':'Frontend build is unavailable'})
    return FileResponse(FRONTEND_INDEX,media_type='text/html')
