#!/usr/bin/env bash
DIST="Ubuntu"
DISTVER="18.04"
DHSIZE="4096" #DHParam Size
LOCAL_INSTALL="false" # Set to true if you want to use a ip address or a local domain as the hostname. This will disable SSL in the web interface.
SQL_ROOTPWD="penis123" #MySQL Root password. Keep this same across both installers if installing both bots
PB1_PWD=$(< /dev/urandom tr -dc A-Z-a-z-0-9 | head -c"${1:-32}";echo;) #PB1 MySQL user password. Randomgenerated string
PB1_BRC_OAUTH="" # Broadcaster OAuth. Leave this empty.

if [ -f $PWD/pb1install.config ]; then
    source $PWD/pb1install.config
    PB1_DB="pb1_$PB1_NAME"
    PB1_USER="pb1_$PB1_NAME"
else
    echo "Config file missing. Exit."
    exit 1
fi

if [[ -z $PB1_ADM || -z $PB1_BRC || -z $PB1_TIMEZONE || -z $PB1_HOST || -z $PB1_NAME ]]; then
    echo "Some config options are undefined"
    exit 1
fi

if [[ -z $PB1_BOT_CLID || -z $PB1_BOT_CLSEC || -z $PB1_SHRD_CLID || -z $PB1_BOT_OAUTH ]]; then
    echo "No credentials specified."
    exit 1
fi

if [ "$LOCAL_INSTALL" == "true" ]
then
    echo "Local install enabled."
    PB1_PROTO="http"
else
    PB1_PROTO="https"
fi

#Validate Sudo
sudo touch /tmp/sudotag
if [ ! -f /tmp/sudotag ]; then
    echo "User cannot sudo. Exit script."
    exit 1
fi

source /etc/lsb-release
if [ "$DISTRIB_ID" != "$DIST" ] || [ "$DISTRIB_RELEASE" != "$DISTVER" ]
then
  echo "Incorrect OS. Only Ubuntu 18.04 LTS is supported."
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

#Configure APT and Install Packages
sudo add-apt-repository universe
sudo apt update && sudo apt upgrade -y
sudo apt install mysql-server redis-server openjdk-8-jdk-headless nginx libssl-dev python3 python3-pip python3-venv uwsgi uwsgi-plugin-python3 -y

#Build APIProxy
cd ~/pb1tmp
git clone https://github.com/zwb3/twitch-api-v3-proxy.git
cd twitch-api-v3-proxy
./gradlew build

#Copy APIProxy and configs to final location
sudo mkdir /opt/apiproxy
sudo tar xvf ./build/distributions/twitch-api-v3-proxy-boot.tar -C /opt/apiproxy --strip-components=1
cat << EOF > $PB1TMP/application.properties
logging.level.root=WARN
logging.level.de.zwb3=DEBUG
server.address=127.0.0.1
server.port=7221
clientId=$PB1_SHRD_CLID
EOF
sudo mv $PB1TMP/application.properties /opt/apiproxy/application.properties
sudo chown -R www-data:www-data /opt/apiproxy

#Setup Systemd unit for APIProxy and start the service
cat << EOF > $PB1TMP/apiproxy.service
[Unit]
Description=twitch-api-v3-proxy
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
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
git clone https://github.com/pajlada/pajbot.git
cd pajbot
python3 -m venv venv
source ./venv/bin/activate
python3 -m pip install wheel
python3 -m pip install -r requirements.txt

#Setup MySQL
cat << EOF > $PB1TMP/allowinvaliddate.cnf
[mysqld]
sql-mode="ALLOW_INVALID_DATES"
EOF

if [ -f /etc/mysql/mysql.conf.d/allowinvaliddate.cnf ]; then
    echo "MySQL mods aleady exist. skip copying"
else
    sudo mv $PB1TMP/allowinvaliddate.cnf /etc/mysql/mysql.conf.d/allowinvaliddate.cnf
    sudo systemctl restart mysql
fi

sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$SQL_ROOTPWD';"
mysql -uroot -p"$SQL_ROOTPWD" <<_EOF_
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
_EOF_

mysql -uroot -p"$SQL_ROOTPWD" -e "CREATE DATABASE $PB1_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;";
mysql -uroot -p"$SQL_ROOTPWD" -e "GRANT ALL PRIVILEGES ON $PB1_DB.* TO '$PB1_USER'@'localhost' IDENTIFIED BY '$PB1_PWD';"

#Setup pb1config
cat << EOF > $PB1TMP/$PB1_NAME.ini
[main]
; display name of the bot account
nickname = $PB1_NAME
; IRC password of the bot account
; authorize this with your bot-specific client ID
; authorize with https://id.twitch.tv/oauth2/authorize?client_id=0f958ce6bf20ba8ea84a21e43ebba1&redirect_uri=https://twitchapps.com/tmi/&response_type=token&scope=channel:moderate+chat:edit+chat:read+whispers:read+whispers:edit
; make sure your bot-specific application has "https://twitchapps.com/tmi/" set as the
; callback URL temporarily for this authorization, change it back afterwards.
password = $PB1_BOT_OAUTH
; login name of the broadcaster
streamer = $PB1_BRC
; login name of the primary admin (will be granted level 2000 initially)
admin = $PB1_ADM
; an additional channel the bot will join and receive commands from.
control_hub = $PB1_HUB
; db connection, format: mysql+pymysql://username:password@host/databasename?charset=utf8mb4
db = mysql+pymysql://$PB1_USER:$PB1_PWD@localhost/$PB1_DB?charset=utf8mb4
;Add the bot as a whisper account so it can be used to send whispers.
add_self_as_whisper_account = 1
; timezone the bot uses internally, e.g. to show the time when somebody was last seen for example
; use the names from this list https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
timezone = $PB1_TIMEZONE
; Set this to 1 (0 otherwise) to allow twitch channel moderators to create highlights
; (twitch channel moderators are completely separate from moderators on the bot, which is level 500 and above)
trusted_mods = 1

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

; streamtip login credentials if you are using pleblist, to get donations info
[streamtip]
client_id = abc
client_secret = def

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

; this is to allow users/admins to login with the bot on the website
; use a bot/channel-specific client id/secret for this
; the application name of this application will be shown to all users/admins
; that want to login on the site.
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
port = 2320
ssl = 0

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

uid = www-data
gid = www-data

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


cat << EOF > $PB1TMP/ssl.conf
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
    include /etc/nginx/harden.conf;

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
    include /etc/nginx/harden.conf;

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
    include /etc/nginx/harden.conf;
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
}
EOF
fi

#nginx hardening, disable unneeded methods
cat << 'EOF' > $PB1TMP/harden.conf
if ($request_method !~ ^(GET|HEAD|POST|DELETE)$ ) {
    return 444;
}
EOF

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

if [ -f /etc/nginx/harden.conf ]; then
    echo "Hardening config already exists. skip copying"
else
    sudo mv $PB1TMP/harden.conf /etc/nginx/harden.conf
fi

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
sudo mv $PB1TMP/pajbot1-$PB1_NAME.conf /etc/nginx/sites-enabled/pajbot1-$PB1_NAME.conf
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx

#Configure pajbot Systemd Units
cat << 'EOF' > $PB1TMP/pajbot-web@.service
[Unit]
Description=pajbot-web for %i
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
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
User=www-data
Group=www-data
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
sudo chown www-data:www-data /srv/pajbot /srv/pajbot-web
sudo chown -R www-data:www-data /opt/pajbot

#Enable systemd services for the bot and start it up.
sudo mv $PB1TMP/pajbot@.service /etc/systemd/system/
sudo mv $PB1TMP/pajbot-web@.service /etc/systemd/system/
sudo systemctl daemon-reload
sleep 2
sudo systemctl enable pajbot@$PB1_NAME
sudo systemctl enable pajbot-web@$PB1_NAME
sudo systemctl start pajbot@$PB1_NAME
echo 'Waiting 45 seconds for bot to initialize and starting the webui after that.'
sleep 45
sudo systemctl start pajbot-web@$PB1_NAME

#Configure Firewall
sudo ufw allow ssh # Allow inbound port 22 for SSH access
sudo ufw allow 'Nginx Full' # Allow inbound ports 80 and 443 for webui access
sudo ufw --force enable # Enable Firewall

#Done
echo "pajbot1 Installed. Access the web interface in $PB1_PROTO://$PB1_HOST"
echo "Remember to change the Bot application callback URL to $PB1_PROTO://$PB1_HOST/login/authorized or you cannot login to the webui."

sudo rm -rf /tmp/sudotag
sudo rm -rf $PB1TMP

exit 0