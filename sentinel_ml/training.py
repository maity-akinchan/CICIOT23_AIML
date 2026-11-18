"""CSV model fitting/export; dataset preparation lives in csv_training."""
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
from .decision import classify, select_policy
from .contract import BASE, FEATURES, CLASSES
from .csv_contract import CONTRACT_ID, CONTRACT_HASH, matrix

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def metrics(y,p):
    truth=np.asarray(y)!='Benign';attack=np.asarray(p)!='Benign'
    return dict(attack_confusion_matrix=confusion_matrix(truth,attack,labels=[False,True]).tolist(),
                benign_false_positive_rate=float(attack[~truth].mean()) if (~truth).any() else None,
                attack_recall=float(attack[truth].mean()) if truth.any() else None,
                test_accuracy=float(accuracy_score(y,p)),test_macro_f1=float(f1_score(y,p,average='macro')),
                confusion_matrix=confusion_matrix(y,p,labels=CLASSES).tolist(),
                classification_report=classification_report(y,p,labels=CLASSES,output_dict=True,zero_division=0))

def fit_export(frame,provenance,output_dir,preprocess=matrix,contract_id=CONTRACT_ID,contract_hash=CONTRACT_HASH):
    X={s:preprocess(frame.loc[frame.split==s,BASE]) for s in ('train','validation','test')}
    y={s:frame.loc[frame.split==s,'label'] for s in X}
    encoder=LabelEncoder().fit(y['train'])
    estimators={
        'xgb':XGBClassifier(n_estimators=300,max_depth=6,learning_rate=.05,subsample=.8,colsample_bytree=.8,
                            objective='multi:softprob',eval_metric='mlogloss',random_state=42,n_jobs=2,tree_method='hist'),
        'rf':RandomForestClassifier(n_estimators=200,min_samples_leaf=5,class_weight='balanced',random_state=42,n_jobs=2),
        'lr':make_pipeline(StandardScaler(),LogisticRegression(max_iter=2000,class_weight='balanced',random_state=42))}
    validation={}
    policies={}
    for name,model in estimators.items():
        model.fit(X['train'],encoder.transform(y['train']) if name=='xgb' else y['train'])
        classes=list(encoder.classes_ if name=='xgb' else model.classes_)
        scores=model.predict_proba(X['validation'])
        policies[name]=select_policy(classes,scores,y['validation'])
        validation[name]=metrics(y['validation'],classify(classes,scores,policies[name]))
    eligible=[name for name in estimators if policies[name]['usable']]
    if not eligible:
        raise ValueError('No model detects attacks within the validation false-positive budget')
    selected=max(eligible,key=lambda k:validation[k]['attack_recall'])
    out=Path(output_dir);out.mkdir(parents=True,exist_ok=True)
    baseline=X['train'].loc[y['train']=='Benign']
    bundles={}
    for name,model in estimators.items():
        probabilities=model.predict_proba(X['validation'].iloc[:32])
        classes=list(encoder.classes_ if name=='xgb' else model.classes_)
        bundle=dict(model_id=name,model_name=name,model=model,label_encoder=encoder if name=='xgb' else None,
            feature_names=list(FEATURES),classes=classes,contract_id=contract_id,contract_hash=contract_hash,
            decision_policy=policies[name],provenance=provenance,metrics={'validation':validation[name]},
            benign_medians=baseline.median().to_dict(),benign_iqr=(baseline.quantile(.75)-baseline.quantile(.25)).to_dict(),
            golden_base=frame.loc[frame.split=='validation',BASE].iloc[:32].to_dict('records'),golden_probabilities=probabilities.tolist(),
            library_versions={k:__import__('importlib.metadata',fromlist=['version']).version(k) for k in ('numpy','pandas','scikit-learn','xgboost','joblib','dpkt')})
        if name==selected:
            pred=classify(classes,model.predict_proba(X['test']),policies[name])
            bundle['metrics']['test']=metrics(y['test'],pred)
        joblib.dump(bundle,out/f'ciciot_22f_{name}.joblib');bundles[name]=sha(out/f'ciciot_22f_{name}.joblib')
    report=dict(selected_model=selected,selection_rule="maximum attack recall within 0.1% validation benign false-positive budget",decision_policies=policies,validation=validation,artifact_hashes=bundles,
                test=joblib.load(out/f'ciciot_22f_{selected}.joblib')['metrics']['test'],
                majority_test_accuracy=float((y['test']==y['train'].value_counts().idxmax()).mean()),provenance=provenance)
    (out/'training_report.json').write_text(json.dumps(report,indent=2))
    return report
