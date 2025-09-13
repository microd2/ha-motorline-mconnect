
UNDER DEVELOPMENT
# Home Assistant Custom Integration: Motorline MCONNECT

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-blue.svg)](https://hacs.xyz/)

This is an **unofficial** [Home Assistant](https://www.home-assistant.io/) custom integration for [Motorline MCONNECT](https://motorline.pt/en/products/electronic-and-control/smart-home/).
It allows control of MCONNNECT lights and shutters directly from Home Assistant.

---

## Installation
### HACS (recommended)
1. Go to **HACS → Integrations** in your Home Assistant UI.
2. Select the three-dot menu → **Custom repositories**.
3. Add this repository URL and select **Integration**.
4. Search for **Motorline MCONNECT** in HACS and install.

### Manual
1. Clone or download this repository.
2. Copy the `custom_components/motorline_mconnect` folder into your Home Assistant `custom_components` directory.
3. Restart Home Assistant.

---

## Configuration
### Overview
The MCONNECT platform requires MFA to log in, so we will need to create a new Gmail account to use with Home Assistant.
1. Create a new Gmail account
2. Add the new Gmail account to MCONNECT
3. Allow this MCONNECT Integration to check for the MFA code

 - In Home Assistant, go to **Settings → Devices & Services**.

 - Add a new integration and search for **MCONNECT**.
 - Enter your **MCONNECT username and password**.
 - These credentials are stored locally in Home Assistant’s storage (/config/.storage) to enable automatic re-login and MFA. Storage is not encrypted; it’s protected by your system’s file permissions. If you’re not comfortable with this, do not use this integration.
 - Once connected, your devices will appear as Home Assistant entities.
---
### 1. Create a new Gmail account
Create a new Gmail account for your HA MCONNECT user.  e.g. WilsonFamilyMConnectHA@gmail.com

### 2. Add a new user in the MCONNECT App:
 1. Log in to your MCONNECT app as an admin
 2. Menu > Users > Add
 3. Enter the email address of the new account you created in Step 1

### 3. Create the new account in MCONNECT
 1. Log out of the MCONNECT app
 2. At the Login screen, select Create Account
 3. Follow the steps, using the new email address you created in Step 1

### 4. Grant permissions to check for the MFA email
1.	Log in to [Google Cloud Console](https://console.cloud.google.com) with the MConnect account you want to use for this integration.    
2.	Go to Select a Project
	a. New Project
b. Project Name = Home Assistant
c. Create
You will arrive at the welcome screen for your new project
5.	Select APIs and Services
a.	Library > Gmail API
b.	Enable
8.	Go to Credentials in the left menu
a.	Create credentials > OAuth Client Id
b.	If prompted, Configure consent screen
c.	Complete the steps
12.	Go to Clients in the left menu and select Web Application
a.	Fill in the name and click Create
b.	Click Add URI
c.	Enter https://my.home-assistant.io/redirect/oauth
This is just a call-back url redirector that allows Gmail to point back to your HA installation – you don’t need to sign up  to anything
d. Press Ok
16.	COPY your client id and client secret to notepad – you will need these later.
17.	Go to Audience
a.	Click Publish
b.	Ignore the warning that your app requires verification. It doesn’t.
18. Go to Data access in the left menu
a. Click Add or remove scopes
b. Look through the pages of scopes and select Gmail API    …/auth/gmail.readonly
c. Click Update
d. Click Save

### 5. Create the Home Assistant credentials
1.	In Home Assistant go to Settings > Devices & Services
2.	In the 3 dot menu at the top select Application Credentials
3.	Click Add application credential
**Integration:**  Motorline MConnect
**Name:** MConnect MFA
**OAuth Client Id:**  the Client Id from Step 4.6
**OAuth client secret:**  The client secret from Step 4.6

### 6. Add the Motorline MConnect Integration to Home Assistant
1.	In Home Assistant, Go to Settings > Integrations
2.	Click Add Integration and add search for Motorline MCONNECT
3.	Enter the email address and password that you added to the MCONNECT app in Step 3
4.	Confirm that you have already created the Home Assistant credentials (that you completed in Step 5)
5.	A browser window will open with a warning that Google hasn’t verified the app we created in Step 4. Which is true, but we don’t care.
a. Click Advanced
b. Click Go to home-assistant.io (unsafe)
c.	Click Continue
6.	Follow my.home-assistant.io steps to redirect your Gmail login to your local HA instance.
a.	Find the URL that your HA instance is listening on.
i.	Open a new browser tab and log in to your Home Assistant 
ii.	Go to Settings → System → Network → Home Assistant URL
iii.	Click Copy
b.	Go back to the my.home-assistant.io tab and paste URL that you just copied
c. Click Ok
d.	Click Link Account 

Your new Motorline MCONNECT integration should be ready to use!



## Disclaimer

- This integration is **unofficial** and **not affiliated with or endorsed by Motorline**.
- It uses the same API as the official MCONNECT app.
- Because MCONNECT does not provide a public API, this integration may stop working at any time without notice.
- No credentials or data are transmitted anywhere except directly to Motorline’s official servers and Gmail login.
- This integration does not collect or send any usage analytics.
- The Gmail credentials are managed by the Home Assistant OAuth Credentials Management function
- Your MCONNECT username and password are stored in Home Assistant’s configuration files in plain text (unencrypted).

****Use of this integration is at your own risk. The author(s) provide it *as-is*, without warranties of any kind, and accept no responsibility for any issues, damages, malfunctions or anything else resulting from its use. Motorline and the Home Assistant project are not involved in, and do not provide support for, this integration.**
**

---

## Support
If you encounter issues:
- Enable debug logging for `custom_components.motorline_mconnect` and check your Home Assistant logs.
- Open an issue in this repository with details about your setup.

---

## License
[MIT License](LICENSE)
