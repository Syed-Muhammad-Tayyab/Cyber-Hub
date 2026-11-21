Cyber Hub UI - Developed by Syed Muhammad Tayyab
================================================

This folder is the app's user interface. The engine serves it at http://127.0.0.1:8765/ and the desktop
window (CyberHub.pyw / CyberHub.exe) shows exactly this page.

  index.html                 the page frame (menu, header, sign-in screens)
  assets/app.css             the theme (dark + light), all styles
  assets/core.js             API client, charts (inline SVG), tables, dialogs, router
  assets/app.js              start-up, sign-in / lock screens, menu, notifications bell
  assets/pages-protect.js    Dashboard, Virus & threat protection
  assets/pages-network.js    Firewall, Network, Device security
  assets/pages-privacy.js    Password vault, Data protection, Accounts & platforms
  assets/pages-tools.js      Website scanner, Threat intelligence, System monitor, Processes & startup
  assets/pages-manage.js     Scheduler, Notifications, Reports & backup, Activity, Settings, Account, About
  assets/icon.png / .ico     app icon (window, tray, installer)

No framework, no build step and no internet needed: edit a file, press the refresh button in the app.
To add a page:  page("my-page", { title, icon, render: async () => h("div", null, ...) })  and list it in NAV (app.js).

Using your own design instead? Replace index.html and call the engine through
../frontend-bridge/cyberhub-api.js (window.CyberHub.*) - it covers every part including the dashboard,
scheduler, notifications, reports and backup.
