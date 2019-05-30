# pajbot1 installer

## Only Ubuntu 18.04, 19.04 and Debian 9 are supported

Check that your domain of choice is already forwarded to the server's IP and ports 80 and 443 are reachable.
If you are behind a NAT, forward ports 80 and 443 to the server.

Set LOCAL_INSTALL to true in the config if you do not have a domain, or if you want to install pajbot1 locally.

If you want to run both bots on the same system with local install, use a local domain like pb1.server.local for example to prevent conflicts with the IP address

Run the script from a standard user that has sudo access.
***
Create 2 apps in the Twitch Developer site at <https://dev.twitch.tv/console/apps> and Call them BOTNAME-PB1-Shared and BOTNAME-PB1-Bot or something similar.

Define the callback URL for Shared as <https://twitchapps.com/tmi>

Define the callback URL for Bot as <https://twitchapps.com/tmi>

Set the Bot URL to <https://pb1.example.com/login/authorized> after you have provided the OAuth token in the script later on. Change the domain to your own. If you have a local install, change https to http in the url.
***
Rename pb1install.config.example to pb1install.config and set the following options as instructed.

Set ```PB1_ADM``` as your twitch username. This user will get level 2000 access to the bot.

Set ```PB1_BRC``` as the broadcasters twitch username in lowercase. Bot will join this channel.

Set ```PB1_BOT_OAUTH``` as a chat oauth token you can generate from here: <https://twitchapps.com/tmi> Login with the bot account.

Set ```PB1_TIMEZONE``` as the timezone used by the bot in a format like Europe/Berlin

Set ```PB1_HOST``` as the domain name you want to use to reach the web interface of the bot. If you have a local install, you can use a IP address or a local domain here.

Set ```PB1_NAME``` as the bot's twitch username. Can be mixed case if the botname has that.

Set ```PB1_HUB``` as the channel you want to use as the control hub. This is not required if you are not planning to run multiple pajbot1 instances

Set ```PB1_SHRD_CLID``` as the Client ID of the shared application you created before.

Set ```PB1_BOT_CLID``` and ```PB1_BOT_CLSEC``` as the Client ID and Secret from the bot application you created before.
***

After install, you can edit the bot config in /opt/pajbot/configs/botname.ini if you want to set more advanced settings.

After editing, restart pajbot services with "systemctl restart pajbot@botname" and "systemctl restart pajbot-web@botname"