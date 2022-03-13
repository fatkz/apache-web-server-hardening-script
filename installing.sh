sudo apt-get install automake
sudo apt-get install apache2-dev
sudo apt install php7.4-cli
sudo apt install --assume-yes libapache2-mod-security2
sudo apt-get install a2enmod
pip3 install -r requirements.txt
sudo a2enmod rewrite
sudo a2enmod headers
sudo a2enmod http2
sudo a2enmod ssl