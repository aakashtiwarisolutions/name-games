import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
r = json.load(open(ROOT / 'results' / 'exp2.json'))
BLUE, ORANGE, GREEN, RED, GREY = '#2F6DB5', '#E07B39', '#3A9D5D', '#D64545', '#8A8F98'
plt.rcParams.update({'font.size': 9, 'axes.spines.top': False, 'axes.spines.right': False})
names = list(r)
labels = ['Standard', 'Random\nrenaming', 'Adversarial\n1 round', 'Adversarial\n2 rounds']
fig, ax = plt.subplots(figsize=(3.5, 2.7))
x = np.arange(len(names))
w = 0.26
series = [([100 * r[n]['recall'] for n in names], 'Recall, no attack', BLUE),
          ([100 * r[n]['robust_recall'] for n in names], 'Recall under adaptive attack', GREEN),
          ([100 * r[n]['adaptive']['budget_4'] for n in names], 'Attack success (4 edits)', RED)]
for i, (v, lab, c) in enumerate(series):
    bars = ax.bar(x + (i - 1) * w, v, w, color=c, label=lab)
    ax.bar_label(bars, fmt='%.0f', fontsize=6.5, padding=1)
ax.set_xticks(x, labels, fontsize=7.5)
ax.set_ylabel('%')
ax.set_ylim(0, 100)
ax.legend(fontsize=7, frameon=False, loc='upper center', bbox_to_anchor=(0.45, -0.2), ncol=2)
fig.tight_layout()
fig.savefig(ROOT / 'figures' / 'defense.pdf', bbox_inches='tight')
fig.savefig(ROOT / 'figures' / 'defense.png', dpi=200, bbox_inches='tight')
print('ok')
