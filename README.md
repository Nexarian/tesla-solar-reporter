# Installation

## Step 1 - Setup
```
virtualenv .venv
source ./.venv/bin/activate
python -m pip install -r https://raw.githubusercontent.com/jasonacox/pypowerwall/refs/heads/main/requirements.txt
pip install -r requirements.txt
```

## Step 2 - Update variables

Edit `INVERTER_DATA` and `USER_EMAIL` with appropriate values.

## Step 3 - Run
```
source ./.venv/bin/activate
sudo -E env PATH="$PATH" ./.venv/bin/python3 ./main.py
```
