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

bp = ROOT / 'results' / 'base.pkl'
if bp.exists():
    base = pickle.load(open(bp, 'rb'))
else:
    base = Blend().fit(H[tr], y[tr])
    base.calibrate(H[va][y[va] == 0])
    pickle.dump(base, open(bp, 'wb'))

def clean_metrics(model, name):
    s = model.scores(H[te])
    out = {}
    for k, v in s.items():
        pred = v >= model.t[k]
        yt = y[te]
        out[k] = {'auc': roc_auc_score(yt, v), 'recall': float(pred[yt == 1].mean()), 'fpr': float(pred[yt == 0].mean()),
                  'threshold': model.t[k]}
    return out

res = {'clean': clean_metrics(base, 'base'), 'sizes': {'train': len(tr), 'val': len(va), 'test': len(te)}}
print(json.dumps(res, indent=1))

test_phish = pd.unique(H[te][y[te] == 1])
test_phish = np.array([h for h in test_phish if not IP_PATTERN.match(h)])
s = base.scores(test_phish)
rng = np.random.default_rng(0)
N = 1500
attack_sets = {}
for k in ['xgb', 'ngram', 'blend']:
    det = test_phish[s[k] >= base.t[k]]
    attack_sets[k] = rng.choice(det, size=min(N, len(det)), replace=False)
    res.setdefault('detected', {})[k] = int(len(det))
res['n_phish_hosts_test'] = int(len(test_phish))

greedy = {}
for k in ['xgb', 'ngram', 'blend']:
    g = greedy_attack(base, k, list(attack_sets[k]), WORDS_TEST, L, budget=4)
    greedy[k] = g
    res.setdefault('greedy', {})[k] = {f'budget_{b}': float(((g['steps'].notna()) & (g['steps'] <= b)).mean()) for b in range(1, 5)}
    res['greedy'][k]['median_queries_success'] = float(g.loc[g['steps'].notna(), 'queries'].median())
    print(k, res['greedy'][k], flush=True)

single = {}
for op in ['tld', 'subdomain', 'keyword', 'hyphen', 'digit', 'word', 'glyph']:
    g = greedy_attack(base, 'blend', list(attack_sets['blend']), WORDS_TEST, L, budget=1, ops={op})
    applicable = g['ops'].map(len) > 0
    single[op] = {'applicable': float(applicable.mean()), 'evasion_all': float(g['steps'].notna().mean()),
                  'evasion_when_applicable': float(g.loc[applicable, 'steps'].notna().mean()) if applicable.any() else 0.0}
    print(op, single[op], flush=True)
res['single_op_blend'] = single

prng = random.Random(0)
rand = {}
for k in ['xgb', 'ngram', 'blend']:
    rand[k] = {}
    for b in range(1, 5):
        adv = [random_edits(h, b, WORDS_TEST, L, prng) for h in attack_sets[k]]
        rand[k][f'budget_{b}'] = float((base.scores(adv)[k] < base.t[k]).mean())
    print('random', k, rand[k], flush=True)
res['random'] = rand

transfer = {}
for src in ['xgb', 'ngram', 'blend']:
    g = greedy[src]
    ok = g[g['steps'].notna()]
    sc = base.scores(list(ok['adv']))
    orig = base.scores(list(ok['host']))
    transfer[src] = {}
    for dst in ['xgb', 'ngram', 'blend']:
        was = orig[dst] >= base.t[dst]
        transfer[src][dst] = float((sc[dst][was] < base.t[dst]).mean()) if was.any() else None
res['transfer'] = transfer
print(json.dumps(transfer, indent=1))

opcount = {}
for ops in greedy['blend'].loc[greedy['blend']['steps'].notna(), 'ops']:
    for o in ops:
        opcount[o] = opcount.get(o, 0) + 1
res['greedy_blend_op_usage'] = opcount
ex = greedy['blend'][greedy['blend']['steps'].notna()].sample(25, random_state=0)
res['examples'] = ex[['host', 'adv', 'steps']].astype(str).values.tolist()
pickle.dump({'greedy': greedy, 'attack_sets': attack_sets}, open(ROOT / 'results' / 'exp1.pkl', 'wb'))
json.dump(res, open(ROOT / 'results' / 'exp1.json', 'w'), indent=1, default=float)
print('done')
