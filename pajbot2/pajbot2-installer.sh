#!/usr/bin/env bash
PB2_PORT="45334"
source /etc/os-release

if [ -f $PWD/pb2install.config ]; then
    source $PWD/pb2install.config 
else
    echo "Config file missing. Exit."
    exit 1
fi

if [[ -z $PB2_ADMID || -z $PB2_HOST || -z $PB2_BOT_CLID || -z $PB2_BOT_CLSEC || -z $PB2_USER_CLID || -z $PB2_USER_CLSEC || -z $PB2_STRM_CLID || -z $PB2_STRM_CLSEC ]]; then
    echo "Some config options are missing."
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
    PB2_PROTO="http"
    PB2_WS_SEC="false"
else
    PB2_PROTO="https"
    PB2_WS_SEC="true"
fi

#Validate Sudo
sudo touch /tmp/sudotag
if [ ! -f /tmp/sudotag ]; then
    echo "User cannot sudo. Exit script."
    exit 1
fi

#Create Tempdir for install files
mkdir ~/pb2tmp
PB2TMP=$HOME/pb2tmp

#Create pajbot user
sudo adduser --shell /bin/bash --system --group pajbot

if [ $ID == "debian" ]; then
sudo apt install curl apt-transport-https -y
fi

#Install Golang
wget https://dl.google.com/go/go$GOVER.linux-amd64.tar.gz -O $PB2TMP/go$GOVER.linux-amd64.tar.gz
sudo tar xvzf $PB2TMP/go$GOVER.linux-amd64.tar.gz -C /usr/local

#Add NodeJS Repo
curl -sL https://deb.nodesource.com/setup_11.x | sudo -E bash -

#Add Dotnet Core Repo
if [ $OS_VER == "debian9" ]
then
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
wget -q https://packages.microsoft.com/config/debian/9/prod.list
sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
elif [ $OS_VER == "ubuntu1804" ]
then
wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O $PB2TMP/packages-microsoft-prod.deb
sudo dpkg -i $PB2TMP/packages-microsoft-prod.deb
elif [ $OS_VER == "ubuntu1904" ]
then
wget -q https://packages.microsoft.com/config/ubuntu/19.04/packages-microsoft-prod.deb -O $PB2TMP/packages-microsoft-prod.deb
sudo dpkg -i $PB2TMP/packages-microsoft-prod.deb
fi

#Configure APT and Install Packages
if [ $ID == "ubuntu" ]; then
sudo add-apt-repository universe
fi
sudo apt update && sudo apt upgrade -y
sudo apt install mariadb-server redis-server nodejs build-essential apt-transport-https dotnet-sdk-2.2 nginx -y

#Configure bash_aliases
{
echo 'export PATH=$PATH:/usr/local/go/bin'
} >> ~/.bashrc
source ~/.bashrc

#Download PB2 and node deps for web, and build the bot as the pajbot user
cat << 'EOF' > /tmp/pajbot_inst.sh
cd $HOME
{
echo 'export PATH=$PATH:/usr/local/go/bin'
} >> ~/.bashrc
source ~/.bashrc
mkdir git
cd git
git clone --recursive https://github.com/pajbot/pajbot2
cd pajbot2
chmod +x ./utils/install.sh && ./utils/install.sh
cd cmd/bot
go get
go build -tags csharp
cd ../../web
npm i
npm run build
cd ..
EOF
sudo chmod 777 /tmp/pajbot_inst.sh
sudo -i -u pajbot /tmp/pajbot_inst.sh
sudo rm /tmp/pajbot_inst.sh

#Setup MySQL
sudo mysql -e "CREATE DATABASE $PB2_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;";
sudo mysql -e "CREATE USER pajbot@localhost IDENTIFIED VIA unix_socket;"
sudo mysql -e "GRANT ALL PRIVILEGES ON pb2.* to 'pajbot'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

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
cat << 'EOF' > $PB2TMP/ssl.conf
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
cat << 'EOF' > $PB2TMP/ssl.conf
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

#Setup http wwwroot to issue the initial certificate
if [[ $LOCAL_INSTALL = "true" ]]
then
    echo 'Local install enabled. Do not generate certificate.'
else

#Setup temporary http webroot to issue the initial certificate
cat << EOF > $PB2TMP/leissue.conf
server {
    listen 80;
    server_name $PB2_HOST;

    location /.well-known/acme-challenge/ {
        alias /var/www/le_root/.well-known/acme-challenge/;
    }
}
EOF
sudo mkdir -p /var/www/le_root/.well-known/acme-challenge
sudo chown -R root:www-data /var/www/le_root
sudo rm /etc/nginx/sites-enabled/default
sudo mv $PB2TMP/leissue.conf /etc/nginx/sites-enabled/0000-issuetmp.conf
sudo systemctl restart nginx
sudo PB2_HOST=$PB2_HOST -S -u root -i /bin/bash -l -c '/root/.acme.sh/acme.sh --issue -d $PB2_HOST -w /var/www/le_root --reloadcmd "systemctl reload nginx"'
sudo rm /etc/nginx/sites-enabled/0000-issuetmp.conf
fi

if [[ $LOCAL_INSTALL = "true" ]]
then
    echo 'Local install enabled. Copy vhost config without ssl settings.'
#pajbot2 vhost no ssl
cat << EOF > $PB2TMP/pajbot2.conf
server {
  listen 80;
  server_name $PB2_HOST;

location / {
   proxy_pass http://127.0.0.1:$PB2_PORT;
   proxy_http_version 1.1;
   proxy_set_header Upgrade \$http_upgrade;
   proxy_set_header Connection "Upgrade";
   include /etc/nginx/proxy_params;
  }
}
EOF
else
#pajbot2 vhost ssl
cat << EOF > $PB2TMP/pajbot2.conf
server {
  listen 80;
  server_name $PB2_HOST;
  
    location /.well-known/acme-challenge/ {
        alias /var/www/le_root/.well-known/acme-challenge/;
    }

    location / {
        return 301 https://\$server_name\$request_uri;
    }

}
server {
  listen 443 ssl http2;
  server_name $PB2_HOST;
  ssl_certificate /root/.acme.sh/$PB2_HOST/fullchain.cer;
  ssl_certificate_key /root/.acme.sh/$PB2_HOST/$PB2_HOST.key;

location / {
   proxy_pass http://127.0.0.1:$PB2_PORT;
   proxy_http_version 1.1;
   proxy_set_header Upgrade \$http_upgrade;
   proxy_set_header Connection "Upgrade";
   include /etc/nginx/proxy_params;
  }
}
EOF
fi

#nginx main config
cat << 'EOF' > $PB2TMP/nginx.conf
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
        sudo mv $PB2TMP/ssl.conf /etc/nginx/conf.d/ssl.conf
    fi
fi

sudo mv $PB2TMP/nginx.conf /etc/nginx/nginx.conf
sudo mv $PB2TMP/pajbot2.conf /etc/nginx/sites-available/pajbot2.conf
sudo ln -s /etc/nginx/sites-available/pajbot2.conf /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx

#Setup pb2config
cat << EOF > $PB2TMP/config.json
{
    "Redis": {
        "Host":"localhost:6379"
    },
    "Admin": {
        "TwitchUserID": "$PB2_ADMID"
    },
    "Web": {
        "Host": "127.0.0.1:$PB2_PORT",
        "Domain": "$PB2_HOST",
        "Secure": $PB2_WS_SEC
    },
    "SQL": {
        "DSN": "pajbot@unix(/var/run/mysqld/mysqld.sock)/$PB2_DB?charset=utf8mb4,utf8&parseTime=true"
    },
    "Auth": {
        "Twitch": {
            "Bot": {
                "ClientID": "$PB2_BOT_CLID",
                "ClientSecret": "$PB2_BOT_CLSEC",
                "RedirectURI": "$PB2_PROTO://$PB2_HOST/api/auth/twitch/bot/callback"
            },
            "User": {
                "ClientID": "$PB2_USER_CLID",
                "ClientSecret": "$PB2_USER_CLSEC",
                "RedirectURI": "$PB2_PROTO://$PB2_HOST/api/auth/twitch/user/callback"
            },
            "Streamer": {
                "ClientID": "$PB2_STRM_CLID",
                "ClientSecret": "$PB2_STRM_CLSEC",
                "RedirectURI": "$PB2_PROTO://$PB2_HOST/api/auth/twitch/streamer/callback"
            }
        }
    }
}
EOF
sudo chown -R pajbot:pajbot $PB2TMP/config.json
sudo mv $PB2TMP/config.json /home/pajbot/git/pajbot2/cmd/bot/config.json

#Setup systemd unit for pajbot2
if [ -f /etc/systemd/system/pajbot2.service ]; then
echo "Systemd config exists. Skipping install"
else
echo "Systemd service missing. Installing service file"
cat << EOF > $PB2TMP/pajbot2.service
[Unit]
Description=pajbot2
After=network.target

[Service]
Type=simple
ExecStart=/home/pajbot/git/pajbot2/cmd/bot/start.sh
WorkingDirectory=/home/pajbot/git/pajbot2/cmd/bot
TimeoutStopSec=5
User=pajbot
Group=pajbot
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sudo mv $PB2TMP/pajbot2.service /etc/systemd/system/pajbot2.service
sudo systemctl daemon-reload
fi

#Start the Bot
sudo systemctl start pajbot2
echo "Waiting for 15 seconds for bot to fully start."
sleep 15
read -r -p "Go to $PB2_PROTO://$PB2_HOST/api/auth/twitch/bot And authorize your bot account. Press enter after this has been done."
sudo systemctl restart pajbot2

echo "pajbot2 Installed. Access the web interface in $PB2_PROTO://$PB2_HOST"

sudo rm -rf /tmp/sudotag
sudo rm -rf $PB2TMP

exit 0