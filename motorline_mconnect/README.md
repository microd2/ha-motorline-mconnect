UNDER DEVELOPMENT
# Home Assistant Custom Integration: Motorline MCONNECT

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-blue.svg)](https://hacs.xyz/)

This is an **unofficial** [Home Assistant](https://www.home-assistant.io/) custom integration for [Motorline MCONNECT](https://mconnect.motorline.pt/).
It allows control of compatible MCONNECT devices (e.g., shutters, lights) directly from Home Assistant.

---

## Features
- Control supported MCONNECT devices from Home Assistant
- Periodic status updates (default: every 3 minutes)
- Secure credential handling via Home Assistant’s Config Entry system

---

## Installation

### HACS (recommended)
1. Go to **HACS → Integrations** in your Home Assistant UI.
2. Select the three-dot menu → **Custom repositories**.
3. Add this repository URL and select **Integration**.
4. Search for **MCONNECT** in HACS and install.

### Manual
1. Clone or download this repository.
2. Copy the `custom_components/motorline_mconnect` folder into your Home Assistant `custom_components` directory.
3. Restart Home Assistant.

---

## Configuration
1. In Home Assistant, go to **Settings → Devices & Services**.
2. Add a new integration and search for **MCONNECT**.
3. Enter your **MCONNECT username and password**.
   - These credentials are stored locally in Home Assistant’s storage (/config/.storage) to enable automatic re-login and MFA. Storage is not encrypted; it’s protected by your system’s file permissions. If you’re not comfortable with this, do not use this integration.
4. Once connected, your devices will appear as Home Assistant entities.

---

## Disclaimer

- This integration is **unofficial** and **not affiliated with or endorsed by Motorline**.
- It uses the same web endpoints as the official MCONNECT web app.
- Because MCONNECT does not provide a public API, this integration may stop working at any time without notice.
- No credentials or data are transmitted anywhere except directly to Motorline’s official servers.
- This integration does not collect or send any usage analytics.

**Use at your own risk. Neither the author(s) of this integration nor the Home Assistant project are responsible for any issues, damages, or malfunctions caused by its use.**

---

## Support
If you encounter issues:
- Enable debug logging for `custom_components.motorline_mconnect` and check your Home Assistant logs.
- Open an issue in this repository with details about your setup.

---

## License
[MIT License](LICENSE)
