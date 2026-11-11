# Name Games

Code and results for the paper "Name Games: Adversarial Domain Renaming Against Machine Learning Phishing Detectors".

The paper attacks the host-only phishing models from QRShield. An attacker renames a phishing host with small, realistic edits (changing the TLD, adding a common word, removing hyphens, digits or keywords, homoglyphs, removing a subdomain level) until the model stops flagging it. We then retrain the models with renamed hosts and attack them again.

## Main results

All numbers are on websites never seen in training, at a 5% false alarm rate.

| | Blend of XGBoost and character n-grams |
|---|---|
| Detected phishing hosts evaded with 1 edit | 48.5% |
| Detected phishing hosts evaded with 4 edits | 83.9% |
| Evaded with a TLD swap alone | 44.7% |
| Evaded with 4 random edits | 10.1% |
| Median queries per successful evasion | 34 |

| Training | Clean recall | Evasion, 4 edits | Recall under attack |
|---|---|---|---|
| Standard | 61.5% | 82.5% | 10.7% |
| Random renaming | 61.3% | 69.8% | 18.5% |
| Adversarial, 1 round | 61.0% | 56.3% | 26.6% |
| Adversarial, 2 rounds | 60.9% | 51.3% | 29.7% |

## Layout

```
src/common.py          data split, models, renaming edits, attacks
src/exp1_attack.py     attacks on the standard models
src/exp2_defense.py    adversarial training and adaptive attacks
src/figures_exp1.py    figures for the attack results
src/figures_exp2.py    figure for the defense results
results/               exp1.json, exp2.json and logs
figures/               figures used in the paper
paper/                 LaTeX source
```

## How to run

This project reuses the feature code from QRShield, so place both folders side by side:

```
ML Projects/
  QRShield/
  rename-attacks/
```

Put `PhiUSIIL_Phishing_URL_Dataset.csv` in `QRShield/data/`, then:

```
pip install -r requirements.txt
cd src
python exp1_attack.py
python exp2_defense.py
python figures_exp1.py
python figures_exp2.py
```

The first script takes about 15 minutes on a laptop and the second about 30 minutes.

## Data

PhiUSIIL Phishing URL Dataset, Prasad and Chandra (2024), UCI Machine Learning Repository. No domains were registered and no live systems were contacted.
