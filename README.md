# Name Games

**Paper:** [Name Games: Adversarial Domain Renaming Against Machine Learning Phishing Detectors](paper/Tiwari_Name_Games_2026.pdf)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24187103.svg)](https://doi.org/10.5281/zenodo.24187103)

**Related project:** [QRShield](https://github.com/aakashtiwarisolutions/QRShield), the real-time QR code scanner whose models are attacked here.

Machine learning models that flag phishing links from the host name alone are useful when a decision has to be made before a page opens, for example when scanning a QR code. But every character such a model sees is chosen by the attacker. This project asks how cheaply an attacker can rename a phishing host to slip past these models, and whether retraining on renamed hosts helps.

## The attack

An attacker takes a phishing host the model catches and renames it with small, realistic edits until the model stops flagging it.

| Edit | Example |
|---|---|
| TLD swap | `sgpay.top` to `sgpay.org` |
| Benign word | `metamaskdesk.com` to `metamaskdeskcity.com` |
| Digit removal | `pay24bank.xyz` to `paybank.xyz` |
| Hyphen removal | `iran-peygiri.ml` to `iranpeygiri.ml` |
| Keyword removal | `login-nab-au.com` to `nab-au.com` |
| Homoglyph | `account` to `acc0unt` |
| Subdomain strip | `a.b.evil.xyz` to `b.evil.xyz` |

Every renamed host must still contain the imitated brand, must be valid DNS, must not take over a known legitimate domain, and must not reduce a host on a shared service to its bare root domain.

Two attackers are compared:

- **Query attacker:** tries every single-edit option, keeps the one with the lowest phishing score, and repeats up to 4 times.
- **Random attacker:** applies random edits without asking the model anything.

## Main results

All numbers are on websites never seen in training, at a 5% false alarm rate.

| | Blend of XGBoost and character n-grams |
|---|---|
| Detected phishing hosts evaded with 1 edit | 48.5% |
| Detected phishing hosts evaded with 4 edits | 83.9% |
| Evaded with a TLD swap alone | 44.7% |
| Evaded with 4 random edits | 10.1% |
| Median queries per successful evasion | 34 |

Swapping a cheap ending like `.top` for `.org` or `.com` was the single most effective trick. The models learned that cheap endings are suspicious, which is true in the data, but the attacker controls that choice completely.

### Defense: adversarial training

The models were retrained with renamed phishing hosts, then attacked again by an attacker using words never seen in training.

| Training | Clean recall | Evasion, 4 edits | Recall under attack |
|---|---|---|---|
| Standard | 61.5% | 82.5% | 10.7% |
| Random renaming | 61.3% | 69.8% | 18.5% |
| Adversarial, 1 round | 61.0% | 56.3% | 26.6% |
| Adversarial, 2 rounds | 60.9% | 51.3% | 29.7% |

Adversarial training nearly triples recall under attack with no loss in clean recall. The cost is that more legitimate sites with unusual names get flagged (19.2% to 28.0% of renamed legitimate hosts).

## Layout

~~~
src/common.py          data split, models, renaming edits, attacks
src/exp1_attack.py     attacks on the standard models
src/exp2_defense.py    adversarial training and adaptive attacks
src/figures_exp1.py    figures for the attack results
src/figures_exp2.py    figure for the defense results
results/               exp1.json, exp2.json and logs
figures/               figures used in the paper
paper/                 LaTeX source and PDF
~~~

## How to run

This project reuses the feature code from QRShield, so place both folders side by side:

~~~
ML Projects/
  QRShield/
  name-games/
~~~

Put `PhiUSIIL_Phishing_URL_Dataset.csv` in `QRShield/data/`, then:

~~~
pip install -r requirements.txt
cd src
python exp1_attack.py
python exp2_defense.py
python figures_exp1.py
python figures_exp2.py
~~~

The first script takes about 15 minutes on a laptop and the second about 30 minutes.

## Limitations

- Renamed domains were not checked for real-world availability, so some may already be registered.
- The edit list and word lists are small, and the greedy attack is not optimal, so real attackers could do better.
- One dataset (PhiUSIIL) and one model family were tested.

## Data

PhiUSIIL Phishing URL Dataset, Prasad and Chandra (2024), UCI Machine Learning Repository. No domains were registered and no live systems were contacted.
