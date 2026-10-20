"""Deterministic, explainable baseline risk policy. Never substitutes for MFA."""

def evaluate(recent_failures:int=0, throttled:bool=False, unfamiliar_client:bool=False, missing_metadata:bool=False):
    score=min(100,max(0,recent_failures)*15 + (20 if throttled else 0) + (10 if unfamiliar_client else 0) + (0 if missing_metadata else 0))
    severity='CRITICAL' if score>=80 else 'HIGH' if score>=60 else 'MEDIUM' if score>=30 else 'LOW'
    decision='BLOCK' if score>=80 else 'STEP_UP_AUTH' if score>=60 else 'MONITOR' if score>=30 else 'ALLOW'
    factors=[]
    if recent_failures: factors.append(f'{recent_failures} recent failed attempts')
    if throttled: factors.append('request throttling occurred')
    if unfamiliar_client: factors.append('unfamiliar client characteristics')
    if not factors: factors.append('no elevated signals observed')
    return {'score':score,'severity':severity,'decision':decision,'factors':factors}
