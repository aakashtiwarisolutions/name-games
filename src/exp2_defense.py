import json
import random
import pickle
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from common import *

d = load()
H, y = d['hosts'], d['y']
L = d['legit_domains']
tr, va, te = d['train'], d['val'], d['test']
base = pickle.load(open(ROOT / 'results' / 'base.pkl', 'rb'))
exp1 = pickle.load(open(ROOT / 'results' / 'exp1.pkl', 'rb'))

train_phish = pd.unique(H[tr][y[tr] == 1])
train_phish = np.array([h for h in train_phish if not IP_PATTERN.match(h)])
rng = np.random.default_rng(1)
order = rng.permutation(len(train_phish))
pool_a = list(train_phish[order[:10000]])
pool_b = list(train_phish[order[10000:20000]])
prng = random.Random(1)

def train_with(extra):
    hosts = np.concatenate([H[tr], np.array(extra)])
    labels = np.concatenate([y[tr], np.ones(len(extra), dtype=int)])
    m = Blend().fit(hosts, labels)
    m.calibrate(H[va][y[va] == 0])
    return m

models = {'Standard training': base}
aug_random = [random_edits(h, prng.randint(1, 3), WORDS_TRAIN, L, prng) for h in pool_a]
models['Random renaming'] = train_with(aug_random)
print('random aug trained', flush=True)

g1 = greedy_attack(base, 'blend', pool_a, WORDS_TRAIN, L, budget=4)
aug1 = list(g1['adv'])
models['Adversarial (1 round)'] = train_with(aug1)
print('adv1 trained', flush=True)

g2 = greedy_attack(models['Adversarial (1 round)'], 'blend', pool_b, WORDS_TRAIN, L, budget=4)
aug2 = aug1 + list(g2['adv'])
models['Adversarial (2 rounds)'] = train_with(aug2)
print('adv2 trained', flush=True)

test_phish = pd.unique(H[te][y[te] == 1])
test_phish = np.array([h for h in test_phish if not IP_PATTERN.match(h)])
legit_test = pd.unique(H[te][y[te] == 0])
legit_sample = list(np.random.default_rng(2).choice(legit_test, 3000, replace=False))
benign_renamed = [random_edits(h, 2, WORDS_TEST, L, random.Random(i)) for i, h in enumerate(legit_sample)]
base_adv = exp1['greedy']['blend']
base_adv = list(base_adv.loc[base_adv['steps'].notna(), 'adv'])

res = {}
for name, m in models.items():
    s = m.scores(H[te])['blend']
    yt = y[te]
    pred = s >= m.t['blend']
    r = {'auc': roc_auc_score(yt, s), 'recall': float(pred[yt == 1].mean()), 'fpr': float(pred[yt == 0].mean())}
    sp = m.scores(test_phish)['blend']
    det = test_phish[sp >= m.t['blend']]
    att = list(np.random.default_rng(0).choice(det, size=min(1500, len(det)), replace=False))
    g = greedy_attack(m, 'blend', att, WORDS_TEST, L, budget=4)
    r['adaptive'] = {f'budget_{b}': float(((g['steps'].notna()) & (g['steps'] <= b)).mean()) for b in range(1, 5)}
    r['adaptive_median_queries'] = float(g.loc[g['steps'].notna(), 'queries'].median()) if g['steps'].notna().any() else None
    r['robust_recall'] = r['recall'] * (1 - r['adaptive']['budget_4'])
    adv_r = [random_edits(h, 4, WORDS_TEST, L, random.Random(i)) for i, h in enumerate(att)]
    r['random_budget_4'] = float((m.scores(adv_r)['blend'] < m.t['blend']).mean())
    r['old_adv_still_evade'] = float((m.scores(base_adv)['blend'] < m.t['blend']).mean())
    r['benign_renamed_flagged'] = float((m.scores(benign_renamed)['blend'] >= m.t['blend']).mean())
    ops = {}
    for o in g.loc[g['steps'].notna(), 'ops']:
        for x in o:
            ops[x] = ops.get(x, 0) + 1
    r['op_usage'] = ops
    res[name] = r
    print(name, json.dumps(r), flush=True)

json.dump(res, open(ROOT / 'results' / 'exp2.json', 'w'), indent=1, default=float)
print('done')
