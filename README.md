## 🧡 The official OrangeFren Plugin 💚

Its functionality is to detect when a user tries to access a website that is a phishing attempt against the users of services listed on [OrangeFren.com](OrangeFren.com) and to present a clear warning.

The plugin communicates with the [OrangeFren.com](OrangeFren.com) server once per hour to update its list of harmful domains. Furthermore the plugin also attempts to warn a user when a domain is visually similar (ex: 3 replaces an E) or the difference is only in the TLD (ex: google.**com** & google.**sc**)

![warning_example](https://github.com/user-attachments/assets/e3af8d72-5b5a-44bf-9d86-e48f9c7ec90c)

If you don't want to install a plugin and prefer to instead block requests to phishing sites at the DNS level by editing /etc/hosts then you can get the phishing domains here:
`https://orangefren.com/api/get_phishing_data/hosts`
