import re
import sys
import random
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent / 'QRShield'))
from qrshield.features import (host_features, FEATURE_NAMES, parse_host, platform_type, _extract,
                               BRANDS, KEYWORDS, IP_PATTERN, LOOKALIKE)

DATA = ROOT.parent / 'QRShield' / 'data' / 'PhiUSIIL_Phishing_URL_Dataset.csv'
CACHE = ROOT / 'results' / 'data.pkl'

SAFE_TLDS = ['com', 'net', 'org', 'io', 'co', 'us']
WORDS_TRAIN = ['online', 'shop', 'news', 'home', 'group', 'store', 'media', 'world', 'hub', 'center', 'studio', 'web']
WORDS_TEST = ['cloud', 'tech', 'blog', 'life', 'city', 'global', 'digital', 'market', 'house', 'zone', 'plus', 'pro']
GLYPHS = [('o', '0'), ('l', '1'), ('e', '3'), ('a', '4'), ('i', '1')]
LABEL = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')


def load():
    if CACHE.exists():
        return pickle.load(open(CACHE, 'rb'))
    urls = pd.read_csv(DATA, encoding='utf-8-sig', usecols=['URL', 'label'])
    urls['phishing'] = 1 - urls['label']
    urls = urls.drop(columns='label').drop_duplicates('URL').reset_index(drop=True)
    domains = urls['URL'].map(lambda u: _extract(u).top_domain_under_public_suffix or _extract(u).domain)
    platform = urls['URL'].map(platform_type).fillna('none')
    keep = np.where((platform == 'none').values)[0]
    y = urls['phishing'].values
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=0).split(keep, y[keep], groups=domains.iloc[keep]))
    tr, te = keep[tr], keep[te]
    trv, va = next(GroupShuffleSplit(n_splits=1, test_size=0.1, random_state=1).split(tr, y[tr], groups=domains.iloc[tr]))
    hosts = urls['URL'].map(parse_host).values
    legit_domains = set(domains[urls['phishing'] == 0])
    d = dict(hosts=hosts, y=y, train=tr[trv], val=tr[va], test=te, train_full=tr, legit_domains=legit_domains)
    pickle.dump(d, open(CACHE, 'wb'))
    return d


_feat_cache = {}


def features(hosts):
    rows = []
    for h in hosts:
        f = _feat_cache.get(h)
        if f is None:
            f = list(host_features('http://' + h).values())
            _feat_cache[h] = f
        rows.append(f)
    return pd.DataFrame(rows, columns=FEATURE_NAMES)


class Blend:
    def __init__(self, seed=0):
        self.xgb = XGBClassifier(n_estimators=400, learning_rate=0.1, max_depth=6, subsample=0.9,
                                 colsample_bytree=0.9, eval_metric='logloss', random_state=seed, n_jobs=2)
        self.ngram = make_pipeline(TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 5), min_df=3, sublinear_tf=True),
                                   LogisticRegression(max_iter=3000, C=2))
        self.t = {}

    def fit(self, hosts, y):
        self.xgb.fit(features(hosts), y)
        self.ngram.fit(list(hosts), y)
        return self

    def scores(self, hosts):
        hosts = list(hosts)
        px = self.xgb.predict_proba(features(hosts))[:, 1]
        pn = self.ngram.predict_proba(hosts)[:, 1]
        return {'xgb': px, 'ngram': pn, 'blend': (px + pn) / 2}

    def calibrate(self, legit_hosts, fpr=0.05):
        s = self.scores(legit_hosts)
        self.t = {k: float(np.quantile(v, 1 - fpr)) for k, v in s.items()}
        return self.t


def build(sub, dom, suf):
    return '.'.join(p for p in (sub, dom, suf) if p)


def clean(host):
    labels = []
    for lab in host.split('.'):
        lab = re.sub('-{2,}', '-', lab).strip('-')
        if lab:
            labels.append(lab)
    return '.'.join(labels)


def brands_in(host):
    plain = host.translate(LOOKALIKE)
    return {b for b in BRANDS if len(b) > 3 and (b in host or b in plain)}


def valid(cand, original_brands, legit_domains, original=None):
    if not cand or len(cand) > 253 or IP_PATTERN.match(cand):
        return False
    if not all(LABEL.match(l) for l in cand.split('.')):
        return False
    p = _extract(cand)
    if not p.domain or not p.suffix:
        return False
    if f'{p.domain}.{p.suffix}' in legit_domains:
        return False
    if original is not None:
        o = _extract(original)
        if o.subdomain and not p.subdomain and p.domain == o.domain and p.suffix == o.suffix:
            return False
    plain = cand.translate(LOOKALIKE)
    return all(b in cand or b in plain for b in original_brands)


def candidates(host, words, legit_domains, original_brands):
    p = _extract(host)
    sub, dom, suf = p.subdomain, p.domain, p.suffix
    out = []
    for t in SAFE_TLDS:
        if t != suf:
            out.append(('tld', build(sub, dom, t)))
    if sub and len(sub.split('.')) > 1:
        labels = sub.split('.')
        for i in range(1, len(labels)):
            out.append(('subdomain', build('.'.join(labels[i:]), dom, suf)))
    for k in KEYWORDS:
        if k in sub or k in dom:
            out.append(('keyword', clean(build(sub.replace(k, '', 1), dom.replace(k, '', 1) if k not in sub else dom, suf))))
    if '-' in dom or '-' in sub:
        out.append(('hyphen', build(sub.replace('-', ''), dom.replace('-', ''), suf)))
    if re.search(r'\d', dom + sub):
        out.append(('digit', clean(build(re.sub(r'\d', '', sub), re.sub(r'\d', '', dom), suf))))
    for w in words:
        out.append(('word', build(sub, dom + w, suf)))
        out.append(('word', build(sub, w + dom, suf)))
    for a, b in GLYPHS:
        if a in dom:
            out.append(('glyph', build(sub, dom.replace(a, b, 1), suf)))
    seen, res = set(), []
    for op, c in out:
        if c != host and c not in seen and valid(c, original_brands, legit_domains, host):
            seen.add(c)
            res.append((op, c))
    return res


def greedy_attack(model, key, hosts, words, legit_domains, budget=4, ops=None):
    t = model.t[key]
    brands = {h: brands_in(h) for h in hosts}
    current = {h: h for h in hosts}
    steps = {h: None for h in hosts}
    used = {h: [] for h in hosts}
    queries = {h: 0 for h in hosts}
    active = list(hosts)
    for step in range(1, budget + 1):
        pool = []
        for h in active:
            for op, c in candidates(current[h], words, legit_domains, brands[h]):
                if ops is None or op in ops:
                    pool.append((h, op, c))
        if not pool:
            break
        s = model.scores([c for _, _, c in pool])[key]
        best = {}
        for (h, op, c), v in zip(pool, s):
            queries[h] += 1
            if h not in best or v < best[h][0]:
                best[h] = (v, op, c)
        nxt = []
        for h in active:
            if h not in best:
                continue
            v, op, c = best[h]
            current[h] = c
            used[h].append(op)
            if v < t:
                steps[h] = step
            else:
                nxt.append(h)
        active = nxt
        if not active:
            break
    return pd.DataFrame({'host': hosts, 'adv': [current[h] for h in hosts], 'steps': [steps[h] for h in hosts],
                         'ops': [used[h] for h in hosts], 'queries': [queries[h] for h in hosts]})


def random_edits(host, k, words, legit_domains, rng):
    brands = brands_in(host)
    cur = host
    for _ in range(k):
        c = candidates(cur, words, legit_domains, brands)
        if not c:
            break
        cur = c[rng.randrange(len(c))][1]
    return cur
