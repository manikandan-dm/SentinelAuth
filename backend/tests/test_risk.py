from app.risk import evaluate

def test_boundaries():
    assert evaluate(1)['score']==15
    assert evaluate(2)['severity']=='MEDIUM'
    assert evaluate(4)['severity']=='HIGH'
    assert evaluate(6)['severity']=='CRITICAL'
    assert evaluate(20)['score']==100

def test_missing_metadata_and_throttle():
    assert evaluate(missing_metadata=True)['score']==0
    assert evaluate(throttled=True)['decision']=='ALLOW'

def test_explainable():
    r=evaluate(2,unfamiliar_client=True)
    assert r['score']==40 and len(r['factors'])==2
