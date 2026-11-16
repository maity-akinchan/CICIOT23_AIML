"""Auto-block only recent live attacks on enrolled devices with a control channel."""
import json
from collections import Counter, defaultdict, deque
from datetime import datetime
from uuid import uuid4
from sqlalchemy import select
from app.models import Device, DeviceAction

class AutoBlocker:
    def __init__(self):
        self.windows=defaultdict(lambda:deque(maxlen=10000))
        self.sent={}

    async def process(self,app,payloads,predictions):
        from app.routers.devices import connections
        now=datetime.utcnow()
        self.sent={key:when for key,when in self.sent.items() if (now-when).total_seconds()<15}
        for payload,prediction in zip(payloads,predictions):
            if payload.capture_mode!='LIVE_INTERFACE' or not prediction.is_anomaly:continue
            key=(payload.dst_ip,prediction.predicted_class)
            queue=self.windows[key]
            queue.append((now,payload.src_ip,prediction.confidence_score))
            while queue and (now-queue[0][0]).total_seconds()>5:queue.popleft()
            if len(queue)<10 or sum(x[2] for x in queue)/len(queue)<.85:continue
            with app.state.sessions.begin() as db:
                d=db.scalar(select(Device).where(Device.ip_address==payload.dst_ip,Device.token.is_not(None)))
                if d is None or not d.auto_block_enabled or d.device_id not in connections:continue
                for ip,_ in Counter(x[1] for x in queue).most_common(10 if prediction.predicted_class=='DDoS' else 1):
                    if ip in json.loads(d.blocked_ips) or (d.device_id,ip) in self.sent:continue
                    reason=f'AI Auto-Blocked {ip} due to {prediction.predicted_class} attack'
                    command={'command_id':str(uuid4()),'action':'BLOCK_IP','payload':{'ip':ip,'reason':reason}}
                    await connections[d.device_id].send_json(command)
                    self.sent[(d.device_id,ip)]=now
                    db.add(DeviceAction(device_id=d.device_id,triggered_by='AI_AUTO',action_type='BLOCK_IP',target_value=ip,reason=reason))
                    await app.state.ws_manager.broadcast({'event_type':'DEVICE_ACTION','device_id':d.device_id,**command})
