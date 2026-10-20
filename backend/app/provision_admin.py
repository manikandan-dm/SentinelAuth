"""Privileged offline operation; never exposed as an HTTP route.
Run after migrations: python -m app.provision_admin verified-user@example.com --confirm
"""
import argparse
from sqlalchemy import select
from app.main import Factory, User, UserSession

def main():
    parser=argparse.ArgumentParser(description='Promote an existing verified SentinelAuth account to admin')
    parser.add_argument('email')
    parser.add_argument('--confirm',action='store_true',help='Confirm this privileged local operation')
    args=parser.parse_args()
    if not args.confirm:
        parser.error('Pass --confirm to perform this privileged operation')
    db=Factory()
    try:
        user=db.scalar(select(User).where(User.email==args.email.strip().lower()))
        if not user or not user.verified:
            raise SystemExit('Account not found or email is not verified; no changes made.')
        user.role='admin'
        for session in db.scalars(select(UserSession).where(UserSession.user_id==user.id,UserSession.revoked==False)).all():
            session.revoked=True
        db.commit()
        print(f'Admin role assigned to {user.email}; existing sessions were revoked.')
    finally:
        db.close()

if __name__=='__main__':
    main()
