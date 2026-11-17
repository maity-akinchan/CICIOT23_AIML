"""Capture-separated training; no test-label-dependent cleaning or synthetic substitutes."""
import hashlib
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from .capture import extract
from .contract import BASE, FEATURES, CLASSES, CONTRACT_ID, CONTRACT_HASH, matrix

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def build_dataset(manifest_path):
    """Manifest explicitly assigns independent recording groups before any extraction."""
    path=Path(manifest_path);items=json.loads(path.read_text());seen={};hashes={};records=[];sources=[]
    for item in items:
        group=item['capture_group'];split=item['split'];label=item['label']
        if split not in ('train','validation','test') or label not in CLASSES:raise ValueError('Invalid split/label')
        if group in seen and seen[group]!=split:raise ValueError('Capture group crosses splits')
        seen[group]=split;p=(path.parent/item['path']).resolve();digest=sha(p)
        if digest in hashes:raise ValueError('Duplicate capture bytes in manifest')
        hashes[digest]=split;stats={}
        with p.open('rb') as stream:rows=list(extract(stream,stats))
        for i,row in enumerate(rows):
            records.append(dict(**row['features_18'],capture_group=group,split=split,label=label,
                                source_sha256=digest,window_id=f'{digest}:{i}'))
        sources.append(dict(**item,sha256=digest,diagnostics=stats))
    frame=pd.DataFrame(records)
    if frame.empty:raise ValueError('No eligible windows')
    for split in ('train','validation','test'):
        part=frame[frame.split==split]
        if set(part.label)!=set(CLASSES):raise ValueError(f'{split} needs independently captured examples of all three classes')
    matrix(frame.loc[:,BASE])
    # Flag exact overlap instead of using holdout labels to curate training.
    fingerprints=pd.util.hash_pandas_object(frame.loc[:,BASE],index=False)
    split_hashes={s:set(fingerprints[frame.split==s]) for s in ('train','validation','test')}
    overlap={f'{a}/{b}':len(split_hashes[a]&split_hashes[b]) for a,b in [('train','validation'),('train','test'),('validation','test')]}
    return frame,dict(contract_id=CONTRACT_ID,contract_hash=CONTRACT_HASH,manifest_sha256=sha(path),sources=sources,exact_feature_overlap=overlap)

def metrics(y,p):
    truth=np.asarray(y)!='Benign';attack=np.asarray(p)!='Benign'
    return dict(attack_confusion_matrix=confusion_matrix(truth,attack,labels=[False,True]).tolist(),
                benign_false_positive_rate=float(attack[~truth].mean()) if (~truth).any() else None,
                attack_recall=float(attack[truth].mean()) if truth.any() else None,
                test_accuracy=float(accuracy_score(y,p)),test_macro_f1=float(f1_score(y,p,average='macro')),
                confusion_matrix=confusion_matrix(y,p,labels=CLASSES).tolist(),
                classification_report=classification_report(y,p,labels=CLASSES,output_dict=True,zero_division=0))

def train(manifest_path,output_dir):
    frame,provenance=build_dataset(manifest_path)
    X={s:matrix(frame.loc[frame.split==s,BASE]) for s in ('train','validation','test')}
    y={s:frame.loc[frame.split==s,'label'] for s in X}
    encoder=LabelEncoder().fit(y['train'])
    estimators={
        'xgb':XGBClassifier(n_estimators=300,max_depth=6,learning_rate=.05,subsample=.8,colsample_bytree=.8,
                            objective='multi:softprob',eval_metric='mlogloss',random_state=42,n_jobs=2,tree_method='hist'),
        'rf':RandomForestClassifier(n_estimators=200,min_samples_leaf=5,class_weight='balanced',random_state=42,n_jobs=2),
        'lr':make_pipeline(StandardScaler(),LogisticRegression(max_iter=2000,class_weight='balanced',random_state=42))}
    validation={}
    for name,model in estimators.items():
        model.fit(X['train'],encoder.transform(y['train']) if name=='xgb' else y['train'])
        pred=model.predict(X['validation'])
        if name=='xgb':pred=encoder.inverse_transform(pred.astype(int))
        validation[name]=metrics(y['validation'],pred)
    selected=max(validation,key=lambda k:validation[k]['test_macro_f1'])
    out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    baseline=X['train'].loc[y['train']=='Benign']
    bundles={}
    for name,model in estimators.items():
        probabilities=model.predict_proba(X['validation'].iloc[:32])
        classes=list(encoder.classes_ if name=='xgb' else model.classes_)
        bundle=dict(model_id=name,model_name=name,model=model,label_encoder=encoder if name=='xgb' else None,
            feature_names=list(FEATURES),classes=classes,contract_id=CONTRACT_ID,contract_hash=CONTRACT_HASH,
            provenance=provenance,metrics={'validation':validation[name]},
            benign_medians=baseline.median().to_dict(),benign_iqr=(baseline.quantile(.75)-baseline.quantile(.25)).to_dict(),
            golden_base=frame.loc[frame.split=='validation',BASE].iloc[:32].to_dict('records'),golden_probabilities=probabilities.tolist(),
            library_versions={k:__import__('importlib.metadata',fromlist=['version']).version(k) for k in ('numpy','pandas','scikit-learn','xgboost','joblib','dpkt')})
        if name==selected:
            pred=model.predict(X['test'])
            if name=='xgb':pred=encoder.inverse_transform(pred.astype(int))
            bundle['metrics']['test']=metrics(y['test'],pred)
        joblib.dump(bundle,out/f'ciciot_22f_{name}.joblib');bundles[name]=sha(out/f'ciciot_22f_{name}.joblib')
    report=dict(selected_by_validation_macro_f1=selected,validation=validation,artifact_hashes=bundles,
                test=joblib.load(out/f'ciciot_22f_{selected}.joblib')['metrics']['test'],
                majority_test_accuracy=float((y['test']==y['train'].value_counts().idxmax()).mean()),provenance=provenance)
    (out/'training_report.json').write_text(json.dumps(report,indent=2))
    return report
