<div align="center">
    <img src="./honeyscanner_logo.png" alt="Honeyscanner logo" width="400">
</div>

# Honeyscanner

Honeyscanner is a vulnerability analyzer for honeypots. It is designed to automatically perform attacks against a given honeypot to determine the likelihood of an attacker pivoting from the honeypot to the real corporate network. The analyzer uses a variety of attacks, ranging from exploiting vulnerable software libraries to DoS, and fuzzing attacks. In the end, an evaluation report is provided to the honeypot administrator, including advice on how to enhance the security of the honeypot.

## Installation 
<!-- 
### Locally from the project's root

`pip install -e .`
`python setup.py install`

### Remotely from github

`pip install git+https://github.com/honeynet/honeyscanner.git`

## Usage

`honeyscanner --config /path/to/config.json --honeypot cowrie`


`python -m honeyscanner-webapp`

# Flask will serve the React app from the build directory. -->

## How to run

**Python: 3.9.12**

### Examples of how to run:
```bash
python3 main.py --honeypot cowrie --honeypot_version 2.5.0 --target_ip 127.0.0.1 --port 2222 --username root --password 1234
```
```bash
python3 main.py --honeypot kippo --honeypot_version 0.9 --target_ip 127.0.0.1 --port 2222
```
