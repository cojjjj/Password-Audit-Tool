# Password Audit Tool

Offline password audit utility for identity security reviews. It checks password hash exports, plaintext password exports, and password policy exports, then writes HTML and JSON reports.

This project is designed to run locally. It does not call cloud APIs, password breach services, or package registries.

## Features

- Finds weak or common passwords using a built-in list and optional local wordlists
- Detects password reuse by identical hashes or matched plaintext values
- Shows password length distribution when plaintext or dictionary matches are available
- Estimates offline crack time for known or matched passwords
- Reviews password policy exports for risky settings
- Produces both HTML and JSON reports
- Hides plaintext passwords from reports by default

## Supported Inputs

Account exports can be CSV or TXT.

CSV columns are detected by common names:

- User columns: `username`, `user`, `account`, `samAccountName`, `email`, `upn`
- Hash columns: `hash`, `password_hash`, `nt_hash`, `nthash`, `md5`, `sha1`, `sha256`, `sha512`
- Plaintext columns: `password`, `plaintext`, `cleartext`
- Optional hash type: `algorithm`, `hash_type`, `type`

TXT formats:

```text
username:hash
username,hash,algorithm
username:RID:LM_HASH:NTLM_HASH:::
hash
```

Supported unsalted hashes:

- NTLM
- MD5
- SHA1
- SHA256
- SHA512

Bcrypt hashes are detected in reports, but this tool does not crack bcrypt.

Policy exports can be JSON, CSV, or key/value text.

## Quick Start

Run the included sample audit:

```powershell
python .\password_audit.py --accounts .\samples\accounts.csv .\samples\pwdump.txt --policy .\samples\policy.json --out .\password_audit_report.html
```

Run against your own files:

```powershell
python .\password_audit.py --accounts C:\path\users.csv --policy C:\path\policy.json --wordlist C:\path\weak-passwords.txt --out C:\path\password_audit_report.html
```

The tool writes a JSON report next to the HTML report unless `--json-out` is provided.

## Example CSV

```csv
username,hash,algorithm
alice,8846f7eaee8fb117ad06bdd830b7586c,ntlm
carol,5f4dcc3b5aa765d61d8327deb882cf99,md5
```

## Public Repo Safety

Do not commit real password exports, real hashes, real policy exports, customer data, or generated reports. The `.gitignore` file blocks common report and sensitive input names, but you should still review changes before every commit.

Safe to publish:

- `password_audit.py`
- `README.md`
- `LICENSE`
- `SECURITY.md`
- `samples/` with synthetic/demo data only

Not safe to publish:

- Real domain password hashes
- Real policy exports
- Real audit reports
- Custom wordlists that contain internal terms, names, or leaked credentials

## Publish To GitHub

From this folder, create a public repo with the GitHub CLI:

```powershell
git init
git add .
git commit -m "Initial public release"
gh repo create password-audit-tool --public --source . --remote origin --push
```

Or create an empty public repo on GitHub, then connect this folder:

```powershell
git init
git add .
git commit -m "Initial public release"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/password-audit-tool.git
git push -u origin main
```

## Responsible Use

Use this tool only on data you own or are authorized to assess. Store exports and reports in a restricted location and delete temporary plaintext exports after review.

## License

MIT
