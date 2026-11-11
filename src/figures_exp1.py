import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
r = json.load(open(ROOT / 'results' / 'exp1.json'))
BLUE, ORANGE, GREEN, RED, GREY = '#2F6DB5', '#E07B39', '#3A9D5D', '#D64545', '#8A8F98'
plt.rcParams.update({'font.size': 9, 'axes.spines.top': False, 'axes.spines.right': False, 'text.color': 'black',
                     'axes.labelcolor': 'black', 'xtick.color': 'black', 'ytick.color': 'black'})

fig, ax = plt.subplots(figsize=(3.5, 3.0))
b = [0, 1, 2, 3, 4]
for key, name, c, m in [('xgb', 'XGBoost (48 features)', BLUE, 'o'), ('ngram', 'Character n-grams', ORANGE, 's'), ('blend', 'Blend', GREEN, '^')]:
    ax.plot(b, [0] + [100 * r['greedy'][key][f'budget_{i}'] for i in range(1, 5)], marker=m, color=c, label=f'{name}, query attack', ms=4)
ax.plot(b, [0] + [100 * r['random']['blend'][f'budget_{i}'] for i in range(1, 5)], ls='--', marker='x', color=GREY, label='Blend, random edits', ms=4)
ax.set_xlabel('Edit budget (number of renaming edits)')
ax.set_ylabel('Evasion rate (%)')
ax.set_xticks(b)
ax.set_ylim(0, 100)
ax.legend(fontsize=7, frameon=False, loc='upper center', bbox_to_anchor=(0.45, -0.22), ncol=2)
fig.tight_layout()
fig.savefig(ROOT / 'figures' / 'evasion_budget.pdf', bbox_inches='tight')
fig.savefig(ROOT / 'figures' / 'evasion_budget.png', dpi=200, bbox_inches='tight')

names = {'tld': 'TLD swap', 'word': 'Benign word', 'digit': 'Digit removal', 'hyphen': 'Hyphen removal',
         'keyword': 'Keyword removal', 'glyph': 'Homoglyph', 'subdomain': 'Subdomain strip'}
s = r['single_op_blend']
order = sorted(s, key=lambda k: s[k]['evasion_all'])
fig, ax = plt.subplots(figsize=(3.5, 2.4))
y = range(len(order))
ax.barh([i + 0.2 for i in y], [100 * s[k]['evasion_when_applicable'] for k in order], height=0.4, color=ORANGE, label='Among hosts where the edit applies')
ax.barh([i - 0.2 for i in y], [100 * s[k]['evasion_all'] for k in order], height=0.4, color=BLUE, label='Among all detected hosts')
ax.set_yticks(list(y), [names[k] for k in order])
ax.set_xlabel('Evasion with one edit (%)')
ax.legend(fontsize=7, frameon=False, loc='lower right')
fig.tight_layout()
fig.savefig(ROOT / 'figures' / 'single_edit.pdf')
fig.savefig(ROOT / 'figures' / 'single_edit.png', dpi=200)
print('ok')
