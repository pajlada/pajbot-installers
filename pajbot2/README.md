# pajbot2 installer

## Only Ubuntu 18.04 LTS is supported

### The script will overwrite nginx.conf and deletes the default vhost conf file

Check that your domain of choice is already forwarded to the server's IP and ports 80 and 443 are reachable.
If you are behind a NAT, forward ports 80 and 443 to the server.

Set LOCAL_INSTALL to true in the script if you do not have a domain, or if you want to install pajbot2 locally.

If you want to run both bots on the same system with local install, use a local domain like pb2.server.local to prevent conflicts with the IP address

This script will install nodejs repositories and installs golang 1.11.4 into /usr/local/go

~/.bash.aliases file is also updated to set the gopath and disable dotnet telemetry.
***
Create 2 apps in the Twitch Developer site at <https://glass.twitch.tv/console/apps>

Call them BOTNAME-PB2-USER and BOTNAME-PB2-BOT or something similar.

Define the callback URL for the user application as <https://pb2.example.com/api/auth/twitch/user/callback">

Define the callback URL for bot application as <https://pb2.example.com/api/auth/twitch/bot/callback">

Change the domain to your own. If you have a local install, change https to http in the urls.
***
Rename pb2install.config.example to pb2install.config and set the following options as instructed.

Set ```PB2_ADMID``` as the twitch UserID of the admin user.

Set ```PB2_HOST``` as the domain name you want to use to reach the web interface of the bot. If you have a local install, you can use a IP address or a local domain here

Set ```PB2_BOT_CLID``` and ```PB2_BOT_CLSEC``` as the Client ID and Secret from the bot application you created before.

Set ```PB2_USER_CLID``` and ```PB2_USER_CLSEC``` as the Client ID and Secret from the user application you created before.
***
Run the script from a standard user that has sudo access.

After the install, Edit line 178 in $HOME/go/src/github.com/pajlada/pajbot2/web/src/js/Dashboard.jsx and change the userid to the id of the channel you want to use reports in.

After that go to $HOME/go/src/github.com/pajlada/pajbot2/web and run "npm run build". Restart pajbot2 afterwards with "pm2 restart pajbot2"

Go to the bot's channel and type !pb2join channelname to join the bot to other channels