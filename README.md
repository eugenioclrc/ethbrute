# Keystore wallet cracker

Naively implemented in Python, ultra slow, but works, based on [Phildo/ethbrute](https://github.com/Phildo/ethbrute)

## Usage

```shell
python2 brute.py -w wallet.json -p rockyou-60.txt
```

## Requirements

- Python 2.7
- `scrypt_kdf` dependency: `pip install scrypt_kdf`
