# pajbot2 installer

## The script will overwrite nginx.conf and deletes the default vhost conf file

Check that your domain of choice is already forwarded to the server's IP and ports 80 and 443 are reachable.
If you are behind a NAT, forward ports 80 and 443 to the server.

Set LOCAL_INSTALL to true in the config if you do not have a domain, or if you want to install pajbot2 locally.

If you want to run both bots on the same system with a local install, use a local domain like pb2.server.local for example to prevent conflicts with the IP address

Run the script from a standard user that has sudo access.

***
Create 3 apps in the Twitch Developer site at <https://dev.twitch.tv/console/apps>

Call them Botname-PB2-User and Botname-PB2-Bot and Botname-PB2-Streamer or something similar.

Define the callback URL for the user application as <https://pb2.example.com/api/auth/twitch/user/callback">

Define the callback URL for the bot application as <https://pb2.example.com/api/auth/twitch/bot/callback">

Define the callback URL for the streamer application as <https://pb2.example.com/api/auth/twitch/streamer/callback">

Change the domain to your own. If you have a local install, change https to http in the urls.
***
Copy pb2install.config.example to pb2install.config and set the following options as instructed.

Set ```PB2_ADMID``` as the twitch UserID of the admin user.

Set ```PB2_HOST``` as the domain name you want to use to reach the web interface of the bot. If you have a local install, you can use a IP address or a local domain here

Set ```PB2_BOT_CLID``` and ```PB2_BOT_CLSEC``` as the Client ID and Secret from the bot application you created before.

Set ```PB2_USER_CLID``` and ```PB2_USER_CLSEC``` as the Client ID and Secret from the user application you created before.

Set ```PB2_STRM_CLID``` and ```PB2_STRM_CLSEC``` as the Client ID and Secret from the streamer application you created before.
***

Go to the bot's channel and type !pb2join channelname to join the bot to other channels