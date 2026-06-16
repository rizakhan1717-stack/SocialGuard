# SocialGuard - Social Media Threat Intelligence Monitoring Tool

SocialGuard is a Python/Streamlit prototype that monitors social-media-style data for cyber threat indicators. It supports two platform sources in demo mode (Twitter/X-style and Reddit-style records), CSV upload, preprocessing, keyword and behavioural detection, risk scoring, dashboard filtering, MITRE ATT&CK mapping, watchlist matching, analyst recommendations, and CSV/TXT reporting.

## New enhancements in this version
- Threat type classification, such as phishing, malware/botnet, data breach/leak, ransomware, access trading, and exploit activity.
- MITRE ATT&CK-style mapping to tactics and techniques to support analyst investigation.
- Threat actor/watchlist matching for terms such as LockBit, APT28, APT29, Lazarus, BlackCat/ALPHV, and Cl0p.
- Analyst recommendations based on severity and threat type.
- Export as CSV and analyst TXT intelligence report.
- Optional near-real-time dashboard refresh every 30 seconds using `streamlit-autorefresh`.

## Run
```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

## Test
```bash
pytest
```

## Input CSV schema
`id, source, user, text, timestamp, post_count, account_age_days, follower_count`

## Detection model
- Keyword match: +2
- Multiple keyword matches: +1
- High posting activity: +3
- New account: +2
- Low-reputation/high-activity pattern: +1
- Watchlist match: +3
- Score >= 8: Critical Risk
- Score >= 5: High Risk
- Score >= 2: Medium Risk
- Otherwise: Low Risk

## Demo explanation
The tool follows this pipeline:

`Data input -> Preprocessing -> Threat detection -> Risk scoring -> MITRE mapping -> Dashboard visualisation -> Report export`
