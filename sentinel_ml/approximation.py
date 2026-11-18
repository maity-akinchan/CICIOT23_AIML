import hashlib,json
SPEC=dict(id='sentinel-packet-approx22-v1',header='mean transport header bytes',rst='window raw count',window='directed 5-tuple;100 packets;2s timeout;minimum5',other='measured rate/duration/TTL/shares/wire size population statistics',compatibility='approximate Kaggle representation; unverified')
CONTRACT_ID=SPEC['id']
CONTRACT_HASH=hashlib.sha256(json.dumps(SPEC,sort_keys=True).encode()).hexdigest()
WARNING='The packet measurements differ from the training inputs. This model score is unverified and does not trigger an alert.'
