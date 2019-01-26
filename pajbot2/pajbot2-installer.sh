#!/usr/bin/env bash
DIST="Ubuntu"
DISTVER="18.04"
GOVER="1.11.4"
LOCAL_INSTALL="false" # Set to true if you want to use a ip address or a local domain as the hostname. This will disable SSL in the web interface.
PM2_NAME="pajbot2" #PM2 Process name for pajbot2
DHSIZE="4096" #DHParameter Size
PB2_DB="pb2" #PB2 Database Name
PB2_USER="pb2" #PB2 Database User
PB2_PWD=$(< /dev/urandom tr -dc A-Z-a-z-0-9 | head -c"${1:-32}";echo;) #PB2 MySQL password. Randomgenerated string
SQL_ROOTPWD="penis123" #MySQL Root password. Keep this same across both installers if installing both bots
PB2_PORT="45334"
PB2_PATH="$HOME/go/src/github.com/pajlada/pajbot2/cmd/bot" #PB2 Bot directory
PB2_BRANCH="master" #PB2 Git branch to use. Use 'master' for stable and 'develop' for latest code.
source /etc/lsb-release

if [ -f $PWD/pb2install.config ]; then
    source $PWD/pb2install.config 
else
    echo "Config file missing. Exit."
    exit 1
fi

if [[ -z $PB2_ADMID || -z $PB2_HOST ]]; then
    echo "Some config options are undefined"
    exit 1
fi

if [[ -z $PB2_BOT_CLID || -z $PB2_BOT_CLSEC || -z $PB2_USER_CLID || -z $PB2_USER_CLSEC || -z $PB2_STRM_CLID || -z $PB2_STRM_CLSEC ]]; then
    echo "No credentials specified."
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

if [ "$DISTRIB_ID" != "$DIST" ] || [ "$DISTRIB_RELEASE" != "$DISTVER" ]
then
  echo "Incorrect OS. Only Ubuntu 18.04 LTS is supported."
  exit 1
fi

#Create Tempdir for install files
mkdir ~/pb2tmp
PB2TMP=$HOME/pb2tmp

#Install Golang
wget https://dl.google.com/go/go$GOVER.linux-amd64.tar.gz -q -O $PB2TMP/go$GOVER.linux-amd64.tar.gz
sudo tar xvzf $PB2TMP/go$GOVER.linux-amd64.tar.gz -C /usr/local

#Add NodeJS Repo
curl -sL https://deb.nodesource.com/setup_11.x | sudo -E bash -

#Add Dotnet Core Repo
wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O $PB2TMP/packages-microsoft-prod.deb
sudo dpkg -i $PB2TMP/packages-microsoft-prod.deb

#Configure APT and Install Packages
sudo add-apt-repository universe
sudo apt update && sudo apt upgrade -y
sudo apt install mysql-server redis-server nodejs build-essential apt-transport-https dotnet-sdk-2.2 nginx -y
sudo apt-mark hold dotnet-sdk-2.2
sudo updatedb

#Install pm2
sudo npm install pm2 -g
sudo chown -R "$USER":"$USER" /home/"$USER"/.config

#Configure bash_aliases
{
echo 'DOTNET_CLI_TELEMETRY_OPTOUT=1'
echo 'GOROOT=/usr/local/go'
echo 'GOPATH=$HOME/go'
echo 'PATH=$GOPATH/bin:$GOROOT/bin:$PATH'
} >> ~/.bash_aliases

source ~/.bash_aliases

#Define CLRPath as a variable for future uses
CLRPATH=$(dotnet --list-runtimes | grep Microsoft.NETCore.App | tail -1 | awk '{gsub(/\[|\]/, "", $3); print $3 "/" $2}')

#Download PB2 and node deps for web, and build web
go get github.com/pajlada/pajbot2
cd ~/go/src/github.com/pajlada/pajbot2/cmd/bot
git checkout $PB2_BRANCH
git pull
git submodule update --init --recursive
go get -u
cd ~/go/src/github.com/pajlada/pajbot2/web
npm i
npm run build

#Setup MySQL

#Set sql-mode to allow invalid date formats as pb2 uses invalid date formats in it's migrations.
cat << EOF > $PB2TMP/allowinvaliddate.cnf
[mysqld]
sql-mode="ALLOW_INVALID_DATES"
EOF

if [ -f /etc/mysql/mysql.conf.d/allowinvaliddate.cnf ]; then
    echo "MySQL mods aleady exist. skip copying"
else
    sudo mv $PB2TMP/allowinvaliddate.cnf /etc/mysql/mysql.conf.d/allowinvaliddate.cnf
    sudo systemctl restart mysql
fi

#Set root password and secure the database installation
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$SQL_ROOTPWD';"
mysql -uroot -p"$SQL_ROOTPWD" <<_EOF_
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
_EOF_

#Create PB2 database and user.
mysql -uroot -p"$SQL_ROOTPWD" -e "CREATE DATABASE $PB2_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
mysql -uroot -p"$SQL_ROOTPWD" -e "GRANT ALL PRIVILEGES ON $PB2_DB.* TO '$PB2_USER'@'localhost' IDENTIFIED BY '$PB2_PWD';"

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
  include /etc/nginx/harden.conf;

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
  include /etc/nginx/harden.conf;
  return 301 https://\$server_name\$request_uri;
}
server {
  listen 443 ssl http2;
  server_name $PB2_HOST;
  include /etc/nginx/harden.conf;
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

#nginx hardening, disable unneeded methods
cat << 'EOF' > $PB2TMP/harden.conf
if ($request_method !~ ^(GET|HEAD|POST|DELETE)$ ) {
    return 444;
}
EOF

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

if [ -f /etc/nginx/harden.conf ]; then
    echo "Hardening config already exists. skip copying"
else
    sudo mv $PB2TMP/harden.conf /etc/nginx/harden.conf
fi

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
sudo mv $PB2TMP/pajbot2.conf /etc/nginx/sites-enabled/pajbot2.conf
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx

#Setup pb2config and pm2config
cat << EOF > ~/go/src/github.com/pajlada/pajbot2/cmd/bot/config.json
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
        "DSN": "$PB2_USER:$PB2_PWD@tcp(localhost:3306)/$PB2_DB?charset=utf8mb4,utf8&parseTime=true"
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
cat << EOF > ~/go/src/github.com/pajlada/pajbot2/cmd/bot/ecosystem.config.js
module.exports = {
    apps: [{
        name: "$PM2_NAME",
        script: "bot",
        cwd: "$PB2_PATH",
        args: "run",
        env: {
          "LIBCOREFOLDER": "$CLRPATH",
        },
      }
    ]
}
EOF

#Build and Start the Bot
cd ~/go/src/github.com/pajlada/pajbot2
chmod +x ./utils/install.sh && ./utils/install.sh
cd ~/go/src/github.com/pajlada/pajbot2/cmd/bot
go build -tags csharp
pm2 start
echo "Waiting for 15 seconds for bot to fully start."
sleep 15
read -r -p "Go to $PB2_PROTO://$PB2_HOST/api/auth/twitch/bot And authorize your bot account. Press enter after this has been done."
pm2 restart pajbot2

#Configuring Firewall
sudo ufw allow ssh
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

#Configuring pm2 autostartup
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u $USER --hp $HOME
pm2 save

echo "pajbot2 Installed. Access the web interface in $PB2_PROTO://$PB2_HOST"

sudo rm -rf /tmp/sudotag
sudo rm -rf $PB2TMP

exit 0
