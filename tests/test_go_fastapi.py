"""Actual collector binary -> HTTP API -> supplied XGBoost; no retraining."""
import io
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import requests
import numpy as np
import pandas as pd
import pytest
from test_pipeline import capture
from sentinel_ml.artifacts import load,predict
from sentinel_ml.contract import BASE,FEATURES
from sentinel_ml.capture import extract

ROOT=Path(__file__).resolve().parents[1]
GO=os.environ.get('SENTINEL_GO')
@pytest.mark.skipif(not GO,reason='Set SENTINEL_GO to a real Go toolchain executable for cross-process verification')
def test_real_go_to_fastapi(tmp_path):
    env=os.environ.copy();env.pop('SENTINEL_AUTH_DISABLED',None);env['SENTINEL_OPERATOR_TOKEN']='integration-operator-secret';env.update(CGO_ENABLED='0',GOCACHE=os.environ.get('GOCACHE',str(tmp_path/'go-cache')),GOPATH=os.environ.get('GOPATH',str(tmp_path/'go-path')))

    binary=tmp_path/'collector'
    subprocess.run([GO,'build','-o',str(binary),'.'],cwd=ROOT/'collector-go',env=env,check=True)
    source=tmp_path/'syn.pcap';capture(source,step=.0001)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    env.update(DATABASE_URL=f'sqlite:///{tmp_path}/soc.db',MODEL_DIR=str(ROOT/'ml/artifacts'),PYTHONPATH=str(ROOT/'backend-fastapi'))
    import sys
    process=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    base=f'http://127.0.0.1:{port}'
    headers={'Authorization':'Bearer integration-operator-secret'}
    try:
        for _ in range(200):
            try:
                if requests.get(base+'/health',timeout=1).json()['model_loaded']:break
            except requests.RequestException:pass
            time.sleep(.1)
        else:pytest.fail('API did not become ready')
        credential=requests.post(base+'/api/v1/services/credentials',headers=headers,json={'collector_id':'go-sensor-docker0'},timeout=5)
        assert credential.status_code==201,credential.text
        env['SENTINEL_COLLECTOR_TOKEN']=credential.json()['token']
        completed=subprocess.run([str(binary),'--mode','pcap','--pcap-file',str(source),'--replay-speed','0','--api-url',base+'/api/v1/ingest/windows'],capture_output=True,text=True,timeout=30,env=env)
        assert completed.returncode==0,completed.stderr
        flows=requests.get(base+'/api/v1/flows',timeout=5,headers=headers).json()
        assert flows['total']==1
        row=flows['items'][0]
        assert row['input_representation']=='packet_approximation'
        assert row['is_anomaly'] is False
        assert row['features_22']['Header_Length']==5400.0
        assert row['features_22']['rst_count']==0
        with source.open('rb') as stream:reference=list(extract(stream))[0]
        from sentinel_ml.approximation import adapt_window_dict
        bundle=load(ROOT/'ml/artifacts/ciciot_22f_xgb.joblib')
        adapted=adapt_window_dict(reference['features_18'],packet_count=reference['packet_count'],src_ip=reference['src_ip'],dst_ip=reference['dst_ip'])
        x,scores=predict(bundle,pd.DataFrame([adapted],columns=BASE))
        assert np.allclose(list(row['features_22'].values()),x.iloc[0],rtol=1e-5)
        assert np.allclose([row['probabilities'][c] for c in bundle['classes']],scores[0],atol=1e-5)
        exported=requests.get(base+'/api/v1/features/export',params={'capture_session_id':row['capture_session_id']},timeout=5,headers=headers)
        table=pd.read_csv(io.StringIO(exported.text))
        assert list(table.columns)==list(FEATURES)
        assert np.allclose(table.iloc[0],x.iloc[0],rtol=1e-5)
        upload=requests.post(base+'/api/v1/pcap/upload',files={'file':('syn.pcap',source.read_bytes())},timeout=10,headers=headers)
        assert upload.status_code==200,upload.text
        assert requests.get(base+'/api/v1/alerts',headers=headers,timeout=5).json()==[]
        summary=requests.get(base+'/api/v1/overview/summary',headers=headers,timeout=5).json()
        assert summary['active_incidents_count']==0
    finally:
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill();process.wait()
