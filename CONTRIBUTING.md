<!-- Developed by Syed Muhammad Tayyab -->
# 🤝 Contributing to Cyber Hub

Thanks for wanting to help! Cyber Hub protects people's computers, so a few rules matter more than usual.

## 🧰 Set up
```bash
git clone https://github.com/Syed-Muhammad-Tayyab/Cyber-Hub.git
cd Cyber-Hub
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements-desktop.txt
python -m pytest -q          # everything should pass before you start
python CyberHub.pyw          # run the app
```

## 🗺️ Where things live
| You want to change… | Look in |
|---|---|
| An API endpoint | `cyberhub/routers/<area>.py` |
| What a feature does | `cyberhub/services/<area>.py` |
| A page of the app | `ui/assets/pages-*.js` (styles in `ui/assets/app.css`) |
| The database | add a new migration at the end of `MIGRATIONS` in `cyberhub/database.py` — never edit old ones |
| A setting | `DEFAULTS` (+ limits) in `cyberhub/services/settings_store.py` |

## ✅ Rules
1. **Tests first-class.** Every change comes with tests in `tests/`. Use the existing memory backends (`CYBERHUB_FIREWALL_BACKEND=memory` etc.) — tests must never change the real PC or touch the internet.
2. **Never weaken defaults.** Lowering protection must require an administrator; online features stay opt-in.
3. **No shell injection.** User values reach PowerShell only through environment variables (`$env:CH_*`), never inside script text.
4. **No secrets in logs, reports or API answers.**
5. **No real malware** in the repository. Use the EICAR test string.
6. **Plain language in the UI** — write for a person, not a developer.

## 💬 Commits & pull requests
- One topic per pull request, with a short description and screenshots for UI changes.
- Fill in the PR checklist.

By contributing you agree that your work is released under the [MIT License](LICENSE) and that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).

---
<sub>Cyber Hub · Developed by Syed Muhammad Tayyab</sub>
