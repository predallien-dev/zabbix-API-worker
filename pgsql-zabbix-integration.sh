# скрипт работает с базами pg 9 или выше
!/bin/bash

# узнаем версию pg
pg_ver=$(ls /usr | grep pgsql- | cut -b 7-)

# добавляем пользователя, от которого будет осуществлятся мониторинг (без домашней директории)
useradd -d /dev/null -s /usr/sbin/nologin zbx_monitor

# добавляем строчки в конфиг pg_hba.conf
echo -e "host\tall\t\tzbx_monitor\t0.0.0.0/0\t\tmd5" >> /var/lib/pgsql/$pg_ver/data/pg_hba.conf
echo -e "host\tall\t\tzbx_monitor\t127.0.0.1/32\t\ttrust" >> /var/lib/pgsql/$pg_ver/data/pg_hba.conf
echo -e "host\tall\t\tzbx_monitor\t::0/0\t\t\tmd5" >> /var/lib/pgsql/$pg_ver/data/pg_hba.conf

# задаем юзера и пароль для базы pg
sudo -u postgres psql -c "CREATE USER zbx_monitor WITH PASSWORD 'uT?oh3iexi' INHERIT;"
sudo -u postgres psql -c "GRANT pg_monitor TO zbx_monitor;"

# релоад сервиса
sudo -u postgres /usr/pgsql-$pg_ver/bin/pg_ctl reload -D /var/lib/pgsql/$pg_ver/data