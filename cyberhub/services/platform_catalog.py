"""
Cyber Hub Backend - Platform catalog (Part 16)
Developed by Syed Muhammad Tayyab

What Cyber Hub knows about each platform (reviewed 2026-11-13): official domains (link / sender checks), how
important an account there is, which sign-in protections it offers (2FA methods, recovery options), where its
security pages live, and short tips. Platforms change their settings pages - the platform's own Security page is
always the source of truth, so every entry also has an in-app path ("where") to fall back on.

importance  critical = takes over other accounts (e-mail / identity / money / code you publish)
            high     = your public identity, income or customers
            medium   = personal data, purchases, chats
            low      = little harm if lost
mfa         totp (authenticator app), sms, security_key, passkey, app_prompt (approve on a phone), pin (an extra
            PIN / password), email_code
recovery    backup_codes, recovery_email, recovery_phone, recovery_key, trusted_contacts
features    login_alerts, sessions, third_party_apps, ssh_keys, tokens, privacy
sso         the account that really protects this one (YouTube / Gmail / Meet / Chrome -> Google account)
recovers    an e-mail / identity provider: other accounts can be reset through it
"""
from __future__ import annotations

CATALOG_REVIEWED = "2026-11-13"

IMPORTANCE = ("critical", "high", "medium", "low")
IMPORTANCE_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
STRONG_MFA = ("totp", "security_key", "passkey", "app_prompt")
MFA_LABELS = {"totp": "Authenticator app", "sms": "SMS code", "security_key": "Security key", "passkey": "Passkey",
              "app_prompt": "Approve on your phone", "pin": "Extra PIN / password", "email_code": "E-mail code"}
RECOVERY_LABELS = {"backup_codes": "Backup codes", "recovery_email": "Recovery e-mail", "recovery_phone":
                   "Recovery phone", "recovery_key": "Recovery key", "trusted_contacts": "Trusted contacts"}
CATEGORIES = {"identity": "E-mail & identity", "social": "Social media", "messaging": "Messaging & calls",
              "developer": "Developer", "cloud": "Cloud & hosting", "freelance": "Freelance & work",
              "finance": "Money & wallets", "shopping": "Shopping", "entertainment": "Entertainment",
              "productivity": "Productivity & AI", "tools": "Browsers & editors", "custom": "Other"}

SMS_TIP = ("SMS codes can be stolen with a SIM swap - in Pakistan scammers often call pretending to be the "
           "operator. Prefer an authenticator app, passkey or security key where offered.")
OTP_TIP = "Never read a code or OTP out to anyone who calls or messages you - no real company asks for it."


def _p(key, name, cat, domains, imp, mfa=(), rec=(), feat=(), links=None, where=None, sso=None, tips=(),
       recovers=False, brand=None):
    return {"key": key, "name": name, "category": cat, "domains": tuple(domains), "importance": imp,
            "mfa": tuple(mfa), "recovery": tuple(rec), "features": tuple(feat), "links": dict(links or {}),
            "where": where, "sso": sso, "tips": tuple(tips), "recovers": recovers, "brand": brand or key}


PLATFORMS: list[dict] = [
    # ------------------------------------------------------------------ e-mail & identity
    _p("google", "Google account (Gmail, YouTube, Drive, Meet)", "identity",
       ["google.com", "gmail.com", "youtube.com", "google.com.pk", "withgoogle.com", "googleusercontent.com"],
       "critical", ["passkey", "security_key", "app_prompt", "totp", "sms"],
       ["backup_codes", "recovery_email", "recovery_phone"], ["login_alerts", "sessions", "third_party_apps",
                                                             "privacy"],
       {"security": "https://myaccount.google.com/security",
        "mfa": "https://myaccount.google.com/signinoptions/twosv",
        "sessions": "https://myaccount.google.com/device-activity",
        "apps": "https://myaccount.google.com/connections",
        "privacy": "https://myaccount.google.com/data-and-privacy",
        "checkup": "https://myaccount.google.com/security-checkup"},
       "Google Account > Security", tips=("Run Google's Security Checkup once a quarter.",
                                          "A passkey on your phone is the easiest phishing-proof sign-in."),
       recovers=True),
    _p("gmail", "Gmail", "identity", ["gmail.com", "google.com"], "critical", sso="google", recovers=True,
       feat=("third_party_apps",), where="Gmail > Settings > See all settings > Forwarding and POP/IMAP",
       tips=("Check Forwarding and Filters - attackers add a hidden rule that forwards your mail.",), brand="gmail"),
    _p("youtube", "YouTube", "social", ["youtube.com", "youtu.be"], "high", sso="google", feat=("privacy",),
       where="YouTube Studio > Settings > Permissions",
       tips=("Remove channel managers you no longer work with.",
             "Fake 'sponsorship' e-mails with a download are the #1 way channels are stolen."), brand="youtube"),
    _p("google_meet", "Google Meet", "messaging", ["meet.google.com", "google.com"], "low", sso="google",
       where="Meet uses your Google account - secure it under Google Account > Security", brand="google"),
    _p("microsoft", "Microsoft account (Outlook, Teams, OneDrive, Xbox)", "identity",
       ["microsoft.com", "live.com", "outlook.com", "hotmail.com", "office.com", "microsoftonline.com", "xbox.com"],
       "critical", ["passkey", "security_key", "app_prompt", "totp", "sms", "email_code"],
       ["backup_codes", "recovery_email", "recovery_phone"], ["login_alerts", "sessions", "third_party_apps",
                                                             "privacy"],
       {"security": "https://account.microsoft.com/security",
        "mfa": "https://account.live.com/proofs/manage/additional",
        "sessions": "https://account.live.com/Activity",
        "apps": "https://account.live.com/consent/Manage",
        "privacy": "https://account.microsoft.com/privacy"},
       "account.microsoft.com > Security", tips=("Turn on 'Passwordless account' with Microsoft Authenticator.",
                                                 "Print the one-time recovery code and keep it offline."),
       recovers=True),
    _p("outlook", "Outlook / Hotmail", "identity", ["outlook.com", "hotmail.com", "live.com"], "critical",
       sso="microsoft", recovers=True, where="Outlook > Settings > Mail > Rules / Forwarding",
       tips=("Check Rules and Forwarding for anything you did not create.",), brand="outlook"),
    _p("microsoft_teams", "Microsoft Teams", "messaging", ["teams.microsoft.com", "microsoft.com"], "medium",
       sso="microsoft", where="Teams uses your Microsoft account - secure it at account.microsoft.com",
       brand="microsoft"),
    _p("apple", "Apple Account (iCloud)", "identity", ["apple.com", "icloud.com"], "critical",
       ["app_prompt", "security_key", "sms"], ["recovery_key", "trusted_contacts", "recovery_phone"],
       ["sessions", "third_party_apps"], {"security": "https://account.apple.com/account/manage"},
       "Settings > [your name] > Sign-In & Security", tips=("Add a recovery contact or recovery key.",
                                                             "Turn on Stolen Device Protection on your iPhone."),
       recovers=True),
    _p("yahoo", "Yahoo Mail", "identity", ["yahoo.com"], "critical", ["app_prompt", "totp", "sms", "security_key"],
       ["recovery_email", "recovery_phone"], ["sessions", "third_party_apps"],
       {"security": "https://login.yahoo.com/account/security"}, "Account Info > Account Security", recovers=True),
    _p("proton", "Proton Mail", "identity", ["proton.me", "protonmail.com"], "critical",
       ["totp", "security_key"], ["recovery_email", "recovery_phone", "recovery_key"], ["sessions"],
       where="Settings > Account and password", recovers=True),
    # ------------------------------------------------------------------ social
    _p("facebook", "Facebook", "social", ["facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com"], "high",
       ["passkey", "totp", "security_key", "sms", "app_prompt"], ["backup_codes", "recovery_email",
                                                                  "recovery_phone"],
       ["login_alerts", "sessions", "third_party_apps", "privacy"],
       {"security": "https://accountscenter.facebook.com/password_and_security",
        "apps": "https://www.facebook.com/settings?tab=applications",
        "privacy": "https://www.facebook.com/privacy/checkup"},
       "Settings & privacy > Accounts Center > Password and security",
       tips=("Fake 'your page will be disabled' messages are phishing - Meta never asks for your password in chat.",
             "If you run a Page, give admins the lowest role they need.")),
    _p("instagram", "Instagram", "social", ["instagram.com", "facebook.com", "meta.com"], "high",
       ["totp", "sms"], ["backup_codes", "recovery_email", "recovery_phone"],
       ["login_alerts", "sessions", "third_party_apps", "privacy"],
       {"security": "https://accountscenter.instagram.com/password_and_security/"},
       "Settings > Accounts Center > Password and security",
       tips=("Turn off 'Show activity status' and make the account private if it is personal.",
             "'Copyright violation' DMs with a link are phishing.")),
    _p("x", "X (Twitter)", "social", ["x.com", "twitter.com", "t.co"], "high", ["passkey", "security_key", "totp",
                                                                               "sms"],
       ["backup_codes", "recovery_email", "recovery_phone"], ["sessions", "third_party_apps", "privacy"],
       {"security": "https://x.com/settings/security", "mfa": "https://x.com/settings/account/login_verification",
        "sessions": "https://x.com/settings/sessions", "apps": "https://x.com/settings/connected_apps"},
       "Settings > Security and account access", brand="twitter"),
    _p("linkedin", "LinkedIn", "social", ["linkedin.com", "lnkd.in"], "high", ["totp", "sms"],
       ["recovery_email", "recovery_phone"], ["sessions", "third_party_apps", "privacy"],
       {"security": "https://www.linkedin.com/mypreferences/d/sign-in-and-security",
        "mfa": "https://www.linkedin.com/mypreferences/d/two-step-verification",
        "sessions": "https://www.linkedin.com/mypreferences/d/sessions",
        "apps": "https://www.linkedin.com/mypreferences/d/permitted-services"},
       "Me > Settings & Privacy > Sign in & security",
       tips=("Fake recruiter messages with a 'skills test' file or repo are a common attack on developers.",)),
    _p("tiktok", "TikTok", "social", ["tiktok.com"], "medium", ["totp", "sms", "email_code", "passkey"],
       ["recovery_email", "recovery_phone"], ["login_alerts", "sessions", "privacy"],
       where="Profile > Menu > Settings and privacy > Security & permissions"),
    _p("snapchat", "Snapchat", "social", ["snapchat.com"], "medium", ["totp", "sms"],
       ["backup_codes", "recovery_email", "recovery_phone"], ["sessions", "privacy"],
       {"security": "https://accounts.snapchat.com/"}, "Profile > Settings > Two-Factor Authentication"),
    _p("reddit", "Reddit", "social", ["reddit.com"], "low", ["totp"], ["backup_codes", "recovery_email"],
       ["third_party_apps", "privacy"], where="Settings > Account > Two-factor authentication"),
    _p("pinterest", "Pinterest", "social", ["pinterest.com"], "low", ["totp", "sms"], ["recovery_email"],
       ["sessions"], where="Settings > Security and logins"),
    # ------------------------------------------------------------------ messaging
    _p("whatsapp", "WhatsApp", "messaging", ["whatsapp.com", "whatsapp.net", "wa.me"], "high", ["pin", "passkey"],
       ["recovery_email"], ["sessions", "privacy"], where="Settings > Account > Two-step verification",
       tips=("Turn on Two-step verification (6-digit PIN) and add an e-mail to reset it.",
             "Check Settings > Linked devices for computers you don't recognise.",
             "Never share the 6-digit registration code - that is how WhatsApp accounts are hijacked.", OTP_TIP)),
    _p("telegram", "Telegram", "messaging", ["telegram.org", "t.me", "telegram.me"], "medium", ["pin", "passkey"],
       ["recovery_email"], ["sessions", "privacy"], where="Settings > Privacy and Security > Two-Step Verification",
       tips=("Settings > Devices shows every active session - end the ones you don't know.",
             "Hide your phone number: Privacy and Security > Phone Number > Nobody.")),
    _p("discord", "Discord", "messaging", ["discord.com", "discord.gg", "discordapp.com"], "medium",
       ["totp", "security_key", "sms"], ["backup_codes", "recovery_email"], ["sessions", "third_party_apps"],
       where="User Settings > My Account > Enable Authenticator App",
       tips=("'Free Nitro' and 'try my game' links are token stealers.",)),
    _p("slack", "Slack", "messaging", ["slack.com"], "medium", ["totp", "sms"], ["backup_codes"],
       ["sessions", "third_party_apps"], where="Profile > Account settings > Two-factor authentication"),
    _p("zoom", "Zoom", "messaging", ["zoom.us", "zoom.com"], "low", ["totp", "sms"], ["backup_codes"],
       ["sessions"], {"security": "https://zoom.us/profile"}, "Profile > Security > Two-factor authentication"),
    # ------------------------------------------------------------------ developer
    _p("github", "GitHub", "developer", ["github.com", "github.io", "githubusercontent.com"], "critical",
       ["passkey", "security_key", "totp", "app_prompt", "sms"], ["backup_codes"],
       ["sessions", "third_party_apps", "ssh_keys", "tokens"],
       {"security": "https://github.com/settings/security", "sessions": "https://github.com/settings/sessions",
        "apps": "https://github.com/settings/applications", "keys": "https://github.com/settings/keys",
        "tokens": "https://github.com/settings/tokens", "log": "https://github.com/settings/security-log"},
       "Settings > Password and authentication",
       tips=("Use fine-grained tokens with an expiry instead of classic tokens.",
             "Remove SSH keys from old laptops.", "Fake 'job test' repositories that run code on install are a "
                                                  "common attack - read package.json scripts before npm install.")),
    _p("gitlab", "GitLab", "developer", ["gitlab.com"], "high", ["totp", "security_key", "passkey"],
       ["backup_codes"], ["sessions", "ssh_keys", "tokens", "third_party_apps"],
       {"security": "https://gitlab.com/-/user_settings/account",
        "sessions": "https://gitlab.com/-/user_settings/active_sessions",
        "keys": "https://gitlab.com/-/user_settings/ssh_keys",
        "tokens": "https://gitlab.com/-/user_settings/personal_access_tokens"}, "Preferences > Account"),
    _p("bitbucket", "Bitbucket (Atlassian)", "developer", ["bitbucket.org", "atlassian.com"], "high",
       ["totp", "security_key", "passkey"], ["backup_codes"], ["ssh_keys", "tokens", "sessions"],
       {"security": "https://id.atlassian.com/manage-profile/security"}, "Atlassian account > Security"),
    _p("npm", "npm", "developer", ["npmjs.com", "npmjs.org"], "critical", ["security_key", "totp"],
       ["backup_codes"], ["tokens"], where="npmjs.com > Account > Two-Factor Authentication",
       tips=("Require 2FA for publishing and use granular tokens / trusted publishing from CI.",
             "Hijacked maintainer accounts push malware to everyone who installs your package.")),
    _p("pypi", "PyPI", "developer", ["pypi.org", "python.org"], "critical", ["security_key", "totp"],
       ["backup_codes"], ["tokens"], {"security": "https://pypi.org/manage/account/",
                                      "tokens": "https://pypi.org/manage/account/token/"},
       "Account settings > Two factor authentication", tips=("Use project-scoped tokens or trusted publishing.",)),
    _p("docker_hub", "Docker Hub", "developer", ["docker.com", "docker.io"], "high", ["totp"], ["backup_codes"],
       ["tokens"], where="Account settings > Security / Personal access tokens"),
    _p("vscode", "VS Code (Settings Sync, extensions)", "tools", ["code.visualstudio.com", "visualstudio.com",
                                                                   "vscode.dev"], "high",
       sso="github", feat=("extensions",), where="Accounts icon (bottom left) > signed-in accounts",
       tips=("Extensions run with your full user rights - install only from known publishers.",
             "Keep Workspace Trust on, and open unknown projects in Restricted Mode."), brand="microsoft"),
    _p("openai", "OpenAI / ChatGPT", "productivity", ["openai.com", "chatgpt.com"], "medium", ["totp", "passkey"],
       ["backup_codes"], ["sessions"], where="Settings > Security > Multi-factor authentication",
       tips=("Don't paste passwords, keys or client data into chats.",)),
    # ------------------------------------------------------------------ cloud & hosting
    _p("aws", "Amazon Web Services", "cloud", ["aws.amazon.com", "amazonaws.com"], "critical",
       ["passkey", "security_key", "totp"], [], ["tokens", "sessions"],
       {"security": "https://console.aws.amazon.com/iam/home#/security_credentials"},
       "IAM > Security credentials", tips=("Never use the root user day to day; delete root access keys.",
                                           "Set a billing alarm - stolen keys are used for crypto mining."),
       brand="amazon"),
    _p("cloudflare", "Cloudflare", "cloud", ["cloudflare.com"], "critical", ["security_key", "totp"],
       ["backup_codes"], ["tokens"], {"security": "https://dash.cloudflare.com/profile/authentication",
                                      "tokens": "https://dash.cloudflare.com/profile/api-tokens"},
       "My Profile > Authentication"),
    _p("vercel", "Vercel", "cloud", ["vercel.com"], "high", ["totp", "passkey"], ["backup_codes"], ["tokens"],
       where="Account Settings > Authentication"),
    _p("netlify", "Netlify", "cloud", ["netlify.com"], "high", ["totp"], ["backup_codes"], ["tokens"],
       where="User settings > Security"),
    _p("dropbox", "Dropbox", "cloud", ["dropbox.com"], "medium", ["totp", "security_key", "sms"], ["backup_codes"],
       ["sessions", "third_party_apps"], {"security": "https://www.dropbox.com/account/security"},
       "Settings > Security"),
    # ------------------------------------------------------------------ freelance & work
    _p("fiverr", "Fiverr", "freelance", ["fiverr.com"], "high", ["totp", "sms"], ["recovery_email"],
       ["sessions"], where="Profile > Settings > Security",
       tips=("Clients never need your login - 'buyers' asking you to sign in elsewhere are scams.",
             "Don't move a deal to WhatsApp / e-mail; payments outside Fiverr aren't protected.")),
    _p("upwork", "Upwork", "freelance", ["upwork.com"], "high", ["totp", "sms"], ["recovery_email"],
       ["sessions"], where="Settings > Password & Security",
       tips=("'Clients' sending a file or repo to 'test' before hiring are a known malware trick.",)),
    _p("canva", "Canva", "productivity", ["canva.com"], "low", ["totp", "email_code"], ["backup_codes"],
       ["sessions"], where="Settings > Login & security"),
    _p("figma", "Figma", "productivity", ["figma.com"], "medium", ["totp", "sms"], ["backup_codes"], ["sessions"],
       where="Settings > Security"),
    _p("notion", "Notion", "productivity", ["notion.so", "notion.com"], "medium", ["totp", "passkey"],
       ["backup_codes"], ["sessions"], where="Settings > My account > 2-step verification"),
    # ------------------------------------------------------------------ money
    _p("paypal", "PayPal", "finance", ["paypal.com", "paypal.me"], "critical", ["passkey", "totp", "sms"], [],
       ["sessions", "third_party_apps"], {"security": "https://www.paypal.com/myaccount/security/"},
       "Settings > Security", tips=(OTP_TIP,)),
    _p("payoneer", "Payoneer", "finance", ["payoneer.com"], "critical", ["app_prompt", "sms"], [], ["sessions"],
       where="Settings > Security settings", tips=(OTP_TIP,)),
    _p("wise", "Wise", "finance", ["wise.com"], "critical", ["app_prompt", "sms", "passkey"], [], ["sessions"],
       where="Settings > Security and privacy"),
    _p("jazzcash", "JazzCash", "finance", ["jazzcash.com.pk"], "critical", ["pin", "sms"], [], [],
       where="JazzCash app > Settings", tips=("Never share your MPIN or OTP - JazzCash staff never ask for it.",
                                               "Call 4444 only from the official app / website number.", SMS_TIP)),
    _p("easypaisa", "Easypaisa", "finance", ["easypaisa.com.pk"], "critical", ["pin", "sms"], [], [],
       where="Easypaisa app > My Account", tips=("Never share your PIN or OTP - Easypaisa never asks for it.",
                                                 SMS_TIP)),
    _p("binance", "Binance", "finance", ["binance.com"], "critical", ["passkey", "security_key", "totp", "sms",
                                                                      "email_code"],
       [], ["sessions", "tokens"], where="Account > Security",
       tips=("Set an Anti-Phishing Code so real e-mails show it.", "Use a withdrawal address whitelist.")),
    # ------------------------------------------------------------------ shopping & entertainment
    _p("amazon", "Amazon", "shopping", ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "a.co"], "medium",
       ["passkey", "totp", "sms"], [], ["sessions"], {"mfa": "https://www.amazon.com/a/settings/approval"},
       "Your Account > Login & security"),
    _p("daraz", "Daraz", "shopping", ["daraz.pk", "daraz.com"], "low", ["sms", "email_code"], [], [],
       where="Account > Settings", tips=("Pay on delivery or inside the app - never to a seller's own number.",)),
    _p("netflix", "Netflix", "entertainment", ["netflix.com"], "low", [], ["recovery_email", "recovery_phone"],
       ["sessions"], {"sessions": "https://www.netflix.com/ManageDevices"}, "Account > Security",
       tips=("Netflix has no 2FA - use a unique password and 'Sign out of all devices' if in doubt.",)),
    _p("spotify", "Spotify", "entertainment", ["spotify.com"], "low", ["email_code"], ["recovery_email"],
       ["sessions"], where="Account > Security and privacy",
       tips=("Use 'Sign out everywhere' if someone else is using your account.",)),
    _p("steam", "Steam", "entertainment", ["steampowered.com", "steamcommunity.com"], "medium", ["app_prompt",
                                                                                                "email_code"],
       ["recovery_key"], ["sessions"], where="Steam app > Steam Guard", tips=("Write down your Steam Guard "
                                                                               "recovery code.",)),
    # ------------------------------------------------------------------ browsers
    _p("chrome", "Google Chrome (sync, saved passwords, extensions)", "tools", ["google.com"], "high", sso="google",
       feat=("extensions",), where="chrome://settings/security",
       tips=("Turn on Enhanced protection in Safe Browsing.", "Remove extensions you don't use."), brand="google"),
    _p("edge", "Microsoft Edge (sync, extensions)", "tools", ["microsoft.com"], "medium", sso="microsoft",
       feat=("extensions",), where="edge://settings/privacy", brand="microsoft"),
    _p("firefox", "Firefox (Mozilla account, extensions)", "tools", ["mozilla.org", "firefox.com"], "medium",
       ["totp"], ["backup_codes"], ["extensions", "sessions"], where="Mozilla account > Security"),
]
BY_KEY = {p["key"]: p for p in PLATFORMS}
# a custom platform the user names themselves (any site)
CUSTOM = _p("custom", "Other", "custom", [], "medium", ["totp", "sms"], ["recovery_email"], [])

# ====================================================================== checklist items
# applies: callable(platform) -> bool ; weight counts toward the account's score
ITEMS: list[dict] = [
    {"id": "unique_password", "label": "Its own password (used nowhere else)", "weight": 3,
     "help": "One leaked site must not open the others - let the Cyber Hub vault generate one."},
    {"id": "strong_password", "label": "A strong password (Good or Strong)", "weight": 2,
     "help": "A 4-5 word passphrase or a generated 16+ character password."},
    {"id": "two_factor", "label": "Two-step verification (2FA) is on", "weight": 5,
     "help": "Stops someone who has your password from signing in."},
    {"id": "strong_two_factor", "label": "2FA uses an app, passkey or security key (not only SMS)", "weight": 2,
     "help": SMS_TIP},
    {"id": "passkey", "label": "A passkey is set up", "weight": 1,
     "help": "Passkeys can't be phished - the site and your device prove each other."},
    {"id": "backup_codes", "label": "Backup / recovery codes saved safely", "weight": 2,
     "help": "Keep them as a secure note in the Cyber Hub vault or printed at home - not in a photo."},
    {"id": "recovery_email", "label": "Recovery e-mail is yours and protected", "weight": 2,
     "help": "Whoever controls the recovery e-mail can reset this account."},
    {"id": "recovery_phone", "label": "Recovery phone number is current", "weight": 1,
     "help": "An old number can be re-issued to someone else."},
    {"id": "login_alerts", "label": "Alerts for new sign-ins are on", "weight": 1,
     "help": "You hear about a stranger's sign-in straight away."},
    {"id": "sessions_reviewed", "label": "Signed-in devices checked recently", "weight": 1,
     "help": "Sign out of phones / PCs you no longer use."},
    {"id": "apps_reviewed", "label": "Connected apps reviewed", "weight": 1,
     "help": "Old quiz apps, tools and bots may still read your data."},
    {"id": "keys_tokens_reviewed", "label": "SSH keys / access tokens reviewed", "weight": 2,
     "help": "Delete keys from old machines and tokens without an expiry."},
    {"id": "privacy_reviewed", "label": "Privacy settings checked", "weight": 1,
     "help": "Who can see your phone, e-mail, friends and posts."},
    {"id": "mail_rules_reviewed", "label": "Forwarding and filters checked", "weight": 2,
     "help": "Attackers hide a rule that forwards or deletes security e-mails."},
    {"id": "password_after_breach", "label": "Password changed after this site's data breach", "weight": 3,
     "help": "This site lost passwords in a breach - an older password should be considered known."},
]
ITEM_BY_ID = {i["id"]: i for i in ITEMS}
REVIEW_ITEMS = ("sessions_reviewed", "apps_reviewed", "keys_tokens_reviewed", "privacy_reviewed",
                "mail_rules_reviewed")      # these go stale after platform_review_days
STATUSES = ("done", "not_done", "not_applicable", "unknown")


def item_applies(item_id: str, p: dict, has_breach_with_passwords: bool = False) -> bool:
    own = not p.get("sso")
    mfa, rec, feat = set(p["mfa"]), set(p["recovery"]), set(p["features"])
    if item_id in ("unique_password", "strong_password"):
        return own
    if item_id == "two_factor":
        return own and bool(mfa)
    if item_id == "strong_two_factor":
        return own and "sms" in mfa and bool(mfa & set(STRONG_MFA))
    if item_id == "passkey":
        return own and "passkey" in mfa
    if item_id == "backup_codes":
        return own and bool(rec & {"backup_codes", "recovery_key"})
    if item_id == "recovery_email":
        return own and "recovery_email" in rec
    if item_id == "recovery_phone":
        return own and "recovery_phone" in rec
    if item_id == "login_alerts":
        return "login_alerts" in feat
    if item_id == "sessions_reviewed":
        return "sessions" in feat
    if item_id == "apps_reviewed":
        return "third_party_apps" in feat
    if item_id == "keys_tokens_reviewed":
        return bool(feat & {"ssh_keys", "tokens"})
    if item_id == "privacy_reviewed":
        return "privacy" in feat
    if item_id == "mail_rules_reviewed":
        return p["key"] in ("gmail", "outlook", "yahoo", "proton")
    if item_id == "password_after_breach":
        return own and has_breach_with_passwords
    return False


def get(key: str) -> dict:
    return BY_KEY.get(key, CUSTOM)


def public(p: dict) -> dict:
    return {"key": p["key"], "name": p["name"], "category": p["category"],
            "category_label": CATEGORIES.get(p["category"], p["category"]), "domains": list(p["domains"]),
            "importance": p["importance"], "mfa": [{"id": m, "label": MFA_LABELS[m], "strong": m in STRONG_MFA}
                                                   for m in p["mfa"]],
            "recovery": [{"id": r, "label": RECOVERY_LABELS[r]} for r in p["recovery"]],
            "features": list(p["features"]), "links": p["links"], "where": p["where"], "sso": p["sso"],
            "sso_name": BY_KEY[p["sso"]]["name"] if p.get("sso") in BY_KEY else None,
            "tips": list(p["tips"]) + ([SMS_TIP] if "sms" in p["mfa"] and SMS_TIP not in p["tips"] else []),
            "recovers_other_accounts": p["recovers"], "has_2fa": bool(p["mfa"]) or bool(p.get("sso"))}


def platform_for_domain(reg: str) -> dict | None:
    """Which catalog platform owns this registrable domain (identity / own entries first, not SSO children)."""
    best = None
    for p in PLATFORMS:
        if any(reg == d or reg.endswith("." + d) for d in p["domains"]):
            if not p.get("sso"):
                return p
            best = best or p
    return best
