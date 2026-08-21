# Pushing this repository to GitHub

## 1. Create the repository

On github.com: **New repository** → name it `azure-grc-risk-assessment` → **Public** → do **not** initialise with a README, .gitignore or licence (this folder already has them).

## 2. Push from your machine

Open a terminal in this folder and run:

```bash
git init
git add .
git commit -m "Azure cloud security risk assessment (GRC simulation)"
git branch -M main
git remote add origin https://github.com/<your-username>/azure-grc-risk-assessment.git
git push -u origin main
```

If `git push` asks for a password, GitHub wants a **personal access token**, not your account password:
Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token → tick `repo`.

## 3. Before you push — a 60-second check

- [ ] `git status` shows no `.rdp` files (the `.gitignore` blocks them, but confirm)
- [ ] Open two or three screenshots and confirm the black redaction boxes are present
- [ ] The repository is under 25 MB (this one is about 7 MB)

## 4. After pushing

- Add a short repository description and the topics `azure`, `grc`, `risk-assessment`, `nist-csf`, `cis-controls`, `cybersecurity` — topics are how people find portfolio repos.
- Check that `README.md` renders correctly and that the Event Viewer image loads.
- Pin the repository to your GitHub profile.
- Add it to your CV or LinkedIn as a link, with one line: *"Cloud security risk assessment of an internet-exposed Azure VM — 9 scored risks mapped to NIST CSF and CIS Controls v8."*

## 5. If you update it later

```bash
git add .
git commit -m "Describe what changed"
git push
```

---

**Delete this file before pushing** if you would rather it not appear in the repository — it is guidance for you, not part of the deliverable.
