#!/usr/bin/env bash
PB1_BRC_OAUTH="" # Broadcaster OAuth. Leave this empty.
source /etc/os-release

if [ -f $PWD/pb1install.config ]; then
    source $PWD/pb1install.config
    PB1_DB="pb_$PB1_NAME"
    PB1_USER="pb_$PB1_NAME"
else
    echo "Config file missing. Exit."
    exit 1
fi

if [[ -z $PB1_ADM || -z $PB1_BRC || -z $PB1_TIMEZONE || -z $PB1_HOST || -z $PB1_NAME ]]; then
    echo "Some config options are undefined"
    exit 1
fi

if [[ -z $PB1_BOT_CLID || -z $PB1_BOT_CLSEC || -z $PB1_SHRD_CLID ]]; then
    echo "No credentials specified."
    exit 1
fi

if [ $ID == "debian" ] && [ $VERSION_ID == "9" ]
then
    echo "Debian 9 detected"
    OS_VER="debian9"
elif [ $ID == "ubuntu" ] && [ $VERSION_ID == "18.04" ]
then
    echo "Ubuntu 18.04 Detected"
    OS_VER="ubuntu1804"
elif [ $ID == "ubuntu" ] && [ $VERSION_ID == "19.04" ]
then
    echo "Ubuntu 19.04 Detected"
    OS_VER="ubuntu1904"
else
    echo "No supported OS detected. Exit script."
    exit 1
fi

if [ "$LOCAL_INSTALL" == "true" ]
then
    echo "Local install enabled."
    PB1_PROTO="http"
    PB1_WS_PROTO="ws"
else
    PB1_PROTO="https"
    PB1_WS_PROTO="wss"
fi

#Validate Sudo
sudo touch /tmp/sudotag
if [ ! -f /tmp/sudotag ]; then
    echo "User cannot sudo. Exit script."
    exit 1
fi

#Get OAuth token for the broadcaster from the user
if [ -z "$PB1_BRC_OAUTH" ]
then
PB1_BRC_OAUTH_DEF="4d36fa3cc5c0547c60e9c524ba03dd"
read -rp "Ask the broadcaster to open the following url:
https://id.twitch.tv/oauth2/authorize?client_id=$PB1_BOT_CLID&redirect_uri=https://twitchapps.com/tmi/&response_type=token&scope=channel_subscriptions+channel_editor
and input the received oauth key without the oauth: part into this prompt and press enter. If you don't want to do it now, just press enter to skip.  " PB1_BRC_OAUTH
PB1_BRC_OAUTH="${OUT_PATH:-$PB1_BRC_OAUTH_DEF}"
fi

#Create Tempdir for install files
mkdir ~/pb1tmp
PB1TMP=$HOME/pb1tmp

#Create pajbot user
sudo adduser --shell /bin/bash --system --group pajbot

#Configure APT and Install Packages
if [ $ID == "ubuntu" ]; then
sudo add-apt-repository universe
fi
sudo apt update && sudo apt upgrade -y
sudo apt install mariadb-server redis-server openjdk-8-jre-headless nginx libssl-dev python3 python3-pip python3-venv python3-dev uwsgi uwsgi-plugin-python3 git curl build-essential -y

#Install APIProxy
sudo mkdir /opt/apiproxy
sudo curl -L "https://github.com/zwb3/twitch-api-v3-proxy/releases/download/release/twitch-api-v3-proxy-boot.tar" | sudo tar xvf - -C /opt/apiproxy --strip-components=1 --exclude='twitch-api-v3-proxy-boot/application.properties'

cat << EOF > $PB1TMP/application.properties
logging.level.root=WARN
logging.level.de.zwb3=DEBUG
server.address=127.0.0.1
server.port=7221
clientId=$PB1_SHRD_CLID
EOF
sudo mv $PB1TMP/application.properties /opt/apiproxy/application.properties
sudo chown -R pajbot:pajbot /opt/apiproxy

#Setup Systemd unit for APIProxy and start the service
cat << EOF > $PB1TMP/apiproxy.service
[Unit]
Description=twitch-api-v3-proxy
After=network.target

[Service]
Type=simple
User=pajbot
Group=pajbot
WorkingDirectory=/opt/apiproxy
ExecStart=/opt/apiproxy/bin/twitch-api-v3-proxy
RestartSec=1
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo mv $PB1TMP/apiproxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable apiproxy.service
sudo systemctl start apiproxy.service

#Download PB1 and setup venv and deps
cd $PB1TMP
git clone https://github.com/pajbot/pajbot.git
cd pajbot
python3 -m venv venv
source ./venv/bin/activate
python3 -m pip install wheel
python3 -m pip install -r requirements.txt

#Setup MySQL User
sudo mysql -e "CREATE DATABASE $PB1_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;";
sudo mysql -e "CREATE USER pajbot@localhost IDENTIFIED VIA unix_socket;"
sudo mysql -e "GRANT ALL PRIVILEGES ON \`pb\_%\`.* to 'pajbot'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

#Setup pb1config
cat << EOF > $PB1TMP/$PB1_NAME.ini
[main]
; display name of the bot account
nickname = $PB1_NAME
; login name of the broadcaster
streamer = $PB1_BRC
; login name of the primary admin (will be granted level 2000 initially)
admin = $PB1_ADM
; an additional channel the bot will join and receive commands from.
control_hub = $PB1_HUB
; db connection, format: mysql+pymysql://username:password@host/databasename?charset=utf8mb4
db = mysql+pymysql:///$PB1_DB?unix_socket=/var/run/mysqld/mysqld.sock&charset=utf8mb4
; timezone the bot uses internally, e.g. to show the time when somebody was last seen for example
; use the names from this list https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
timezone = $PB1_TIMEZONE
; Set this to 1 (0 otherwise) to allow twitch channel moderators to create highlights
; (twitch channel moderators are completely separate from moderators on the bot, which is level 500 and above)
trusted_mods = 0
; Set this to a valid Wolfram|Alpha App ID to enable wolfram alpha query functionality
; via !add funccommand query|wolframquery query --level 250
;wolfram = ABCDEF-GHIJKLMNOP
; this location/ip is used to localize the queries to a default location.
; https://products.wolframalpha.com/api/documentation/#semantic-location
; if you specify both IP and location, the location will be ignored.
;wolfram_ip = 62.41.0.123
;wolfram_location = Amsterdam

[web]
; enabled web modules, separated by spaces. For example you could make this
; "linefarming pleblist" to enable the pleblist module additionally.
modules = linefarming
; display name of the broadcaster
streamer_name = $PB1_BRC
; domain that the website runs on
domain = $PB1_HOST
; this configures hearthstone decks functionality if you have the module enabled
deck_tab_images = 1

; streamelements login credentials if you are using pleblist, to get donations info
; note that streamelements login with pajbot is dead, since StreamElements removed their OAuth login endpoint.
; just leave these defaults in place
[streamelements]
client_id = abc
client_secret = def

; streamlabs login credentials if you are using pleblist, to get donations info
[streamlabs]
client_id = abc
client_secret = def

; phrases the bot prints when it starts up and exits
[phrases]
welcome = {nickname} {version} running!
quit = {nickname} {version} shutting down...
; optional: you can make the bot print multiple messages on startup/quit,
; for example a common use for this might be to turn emote only mode on when the bot is quit
; and to turn it back off once it's back. (notice the indentation)
;welcome = {nickname} {version} running!
;    .emoteonlyoff
;quit = .emoteonly
;    {nickname} {version} shutting down...

; this is to allow users/admins to login with the bot on the website
; use a bot/channel-specific client id/secret for this
; the application name of this application will be shown to all users/admins
; that want to login on the site.
; the client_id and client_secret values are required to authorize the bot and get its access token to join chat
[webtwitchapi]
client_id = $PB1_BOT_CLID
client_secret = $PB1_BOT_CLSEC
redirect_uri = $PB1_PROTO://$PB1_HOST/login/authorized

; this allows the bot to act on behalf of the broadcaster, i.e.
; set the game and title and get the amount/status of subscribers.
; Let your broadcaster do an authorization using this link (use the bot-specific client ID):
; https://id.twitch.tv/oauth2/authorize?client_id=0bb4b8517c0b20e0a72ddbfd88aa69&redirect_uri=https://twitchapps.com/tmi/&response_type=token&scope=channel_subscriptions+channel_editor
; note that you temporarily have to edit your bot-specific twitch app with the
; redirect URL "https://twitchapps.com/tmi/". (If you haven't done so already.) Edit it back to
; "https://bot.kkonatestbroadcaster.tv/login/authorized" afterwards.

[twitchapi]
client_id = $PB1_BOT_CLID
oauth = $PB1_BRC_OAUTH
update_subscribers = 0

; you can optionally populate this with twitter access tokens
; if you want to be able to interact with twitter.
[twitter]
consumer_key = abc
consumer_secret = abc
access_token = 123-abc
access_token_secret = abc
streaming = 0

; leave these for normal bot operation
[flags]
silent = 0
; enables !eval
dev = 1

[websocket]
enabled = 1
port = 2337
host = $PB1_WS_PROTO://$PB1_HOST/clrsocket

; you can optionally populate this for pleblist
[youtube]
developer_key = abc

; This socket lets the bot process and the web process communicate
; This is NOT the socket of the uwsgi process to proxy web requests to
[sock]
sock_file = /srv/pajbot/.$PB1_NAME.sock
EOF
cat << EOF > $PB1TMP/uwsgi_shared.ini
[uwsgi]
module = app:app

master = true
processes = 1
threads = 1
workers = 1

uid = pajbot
gid = pajbot

chmod-socket = 777
vacuum = true
die-on-term = true

plugins = python3,router_cache

memory-report = true
EOF

#Install acme.sh to manage ssl certs
if [[ $LOCAL_INSTALL = "true" ]]
then
    echo 'Local install enabled. Do not install acme.sh'
else
    if sudo test -f "/root/.acme.sh/acme.sh"; then
        echo "acme.sh already installed. skip"
    else
        sudo -S -u root -i /bin/bash -l -c 'curl https://raw.githubusercontent.com/Neilpang/acme.sh/master/acme.sh | INSTALLONLINE=1  sh'
    fi
fi

#Configure nginx
if [[ $LOCAL_INSTALL = "true" ]]
then
    echo 'Local install enabled. Do not generate DHParams'
else
    if [ -f /etc/nginx/dhparam.pem ]; then
        echo "DHParams exist. Skip generation"
    else
        sudo openssl dhparam -out /etc/nginx/dhparam.pem -dsaparam $DHSIZE
    fi
fi


if [ $OS_VER == "ubuntu1904" ]
then
cat << 'EOF' > $PB1TMP/ssl.conf
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_ecdh_curve secp384r1;
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
add_header Strict-Transport-Security "max-age=63072000";
add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
EOF
else
cat << 'EOF' > $PB1TMP/ssl.conf
ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_ecdh_curve secp384r1;
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
add_header Strict-Transport-Security "max-age=63072000";
add_header X-Frame-Options SAMEORIGIN;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
EOF
fi

if [[ $LOCAL_INSTALL = "true" ]]
then
    echo 'Local install enabled. Do not generate certificate.'
else
#Setup temporary http webroot to issue the initial certificate
cat << EOF > $PB1TMP/leissue.conf
server {
    listen 80;
    server_name $PB1_HOST;

    location /.well-known/acme-challenge/ {
        alias /var/www/le_root/.well-known/acme-challenge/;
    }
}
EOF
sudo mkdir -p /var/www/le_root/.well-known/acme-challenge
sudo chown -R root:www-data /var/www/le_root
sudo rm /etc/nginx/sites-enabled/default
sudo mv $PB1TMP/leissue.conf /etc/nginx/sites-enabled/0000-issuetmp.conf
sudo systemctl restart nginx
sudo PB1_HOST=$PB1_HOST -S -u root -i /bin/bash -l -c '/root/.acme.sh/acme.sh --issue -d $PB1_HOST -w /var/www/le_root --reloadcmd "systemctl reload nginx"'
sudo rm /etc/nginx/sites-enabled/0000-issuetmp.conf
fi

if [[ $LOCAL_INSTALL = "true" ]]
then
    echo 'Local install enabled. Copy vhost config without ssl settings.'
#pb1 vhost no ssl
cat << EOF > $PB1TMP/pajbot1-$PB1_NAME.conf
upstream $PB1_NAME-botsite {
    server unix:///srv/pajbot-web/.$PB1_NAME.sock;
}

server {
    listen 80;
    server_name $PB1_HOST;

    charset utf-8;

    location /api/ {
        uwsgi_pass $PB1_NAME-botsite;
        include uwsgi_params;
        expires epoch;
    }

    location / {
        uwsgi_pass $PB1_NAME-botsite;
        include uwsgi_params;
        expires epoch;
        add_header Cache-Control "public";
    }

    location /clrsocket {
        proxy_pass http://127.0.0.1:2337;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
}
EOF
else
#pb1 vhost ssl
cat << EOF > $PB1TMP/pajbot1-$PB1_NAME.conf
upstream $PB1_NAME-botsite {
    server unix:///srv/pajbot-web/.$PB1_NAME.sock;
}
server {
    listen 80;
    server_name $PB1_HOST;

    location /.well-known/acme-challenge/ {
        alias /var/www/le_root/.well-known/acme-challenge/;
    }

    location / {
        return 301 https://\$server_name\$request_uri;
    }

}

server {
    listen 443 ssl http2;
    server_name $PB1_HOST;
    ssl_certificate /root/.acme.sh/$PB1_HOST/fullchain.cer;
    ssl_certificate_key /root/.acme.sh/$PB1_HOST/$PB1_HOST.key;

    charset utf-8;

    location /api/ {
        uwsgi_pass $PB1_NAME-botsite;
        include uwsgi_params;
        expires epoch;
    }

    location / {
        uwsgi_pass $PB1_NAME-botsite;
        include uwsgi_params;
        expires epoch;
        add_header Cache-Control "public";
    }

    location /clrsocket {
        proxy_pass http://127.0.0.1:2337;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
    }
}
EOF
fi

#nginx main config
cat << 'EOF' > $PB1TMP/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
}

http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        server_tokens off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        log_format customformat '[$time_local] $remote_addr '
                '$host "$request" $status '
                '"$http_referer" "$http_user_agent"';

        access_log /var/log/nginx/access.log customformat;
        error_log /var/log/nginx/error.log;

        gzip on;

        server {
                listen       80  default_server;
                server_name  _;
                return       404;
        }

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

EOF

if [[ $LOCAL_INSTALL = "true" ]]
then
    echo 'Local install enabled. Do not copy ssl config.'
else
    if [ -f /etc/nginx/conf.d/ssl.conf ]; then
        echo "SSL config exists. skip copy"
    else
        sudo mv $PB1TMP/ssl.conf /etc/nginx/conf.d/ssl.conf
    fi
fi

sudo mv $PB1TMP/nginx.conf /etc/nginx/nginx.conf
sudo mv $PB1TMP/pajbot1-$PB1_NAME.conf /etc/nginx/sites-available/pajbot1-$PB1_NAME.conf
sudo ln -s /etc/nginx/sites-available/pajbot1-$PB1_NAME.conf /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx

#Configure pajbot Systemd Units
cat << 'EOF' > $PB1TMP/pajbot-web@.service
[Unit]
Description=pajbot-web for %i
After=network.target

[Service]
Type=simple
User=pajbot
Group=pajbot
WorkingDirectory=/opt/pajbot
ExecStart=/usr/bin/uwsgi --ini uwsgi_shared.ini --ini uwsgi_cache.ini --socket /srv/pajbot-web/.%i.sock --pyargv "--config configs/%i.ini" --virtualenv venv
RestartSec=2
Restart=always

[Install]
WantedBy=multi-user.target
EOF
cat << 'EOF' > $PB1TMP/pajbot@.service
[Unit]
Description=pajbot for %i
After=network.target

[Service]
Type=simple
User=pajbot
Group=pajbot
WorkingDirectory=/opt/pajbot
Environment=VIRTUAL_ENV=/opt/pajbot/venv
ExecStart=/bin/bash -c "PATH=$VIRTUAL_ENV/bin:$PATH /opt/pajbot/venv/bin/python3 main.py --config configs/%i.ini"
RestartSec=2
Restart=always

[Install]
WantedBy=multi-user.target
EOF

#Install Bot
cd $PB1TMP/pajbot
mkdir configs
mv $PB1TMP/$PB1_NAME.ini configs/$PB1_NAME.ini
mv $PB1TMP/uwsgi_shared.ini $PB1TMP/pajbot/
sudo cp -r $PB1TMP/pajbot /opt/pajbot
cd /opt/pajbot
sudo mkdir /srv/pajbot /srv/pajbot-web
sudo chown pajbot:pajbot /srv/pajbot /srv/pajbot-web
sudo chown -R pajbot:pajbot /opt/pajbot

#Enable systemd services for the bot and start it up.
sudo mv $PB1TMP/pajbot@.service /etc/systemd/system/
sudo mv $PB1TMP/pajbot-web@.service /etc/systemd/system/
sudo systemctl daemon-reload
sleep 2
sudo systemctl enable pajbot@$PB1_NAME
sudo systemctl enable pajbot-web@$PB1_NAME
sudo systemctl start pajbot@$PB1_NAME
echo 'Waiting 30 seconds for bot to initialize and starting the webui after that.'
sleep 30
sudo systemctl start pajbot-web@$PB1_NAME

#Done
echo "pajbot1 Installed. Access the web interface in $PB1_PROTO://$PB1_HOST"
echo "Access $PB1_PROTO://$PB1_HOST/bot_login and login with your bot account."
echo "Remember to change the Bot application callback URL to $PB1_PROTO://$PB1_HOST/login/authorized or you cannot login to the webui."

sudo rm -rf /tmp/sudotag
sudo rm -rf $PB1TMP

exit 0