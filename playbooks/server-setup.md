# Server Setup

Create group:

    $ groupadd --gid 1504 badgeblue

Create user:

    $ useradd --home-dir /var/lib/badgeblue --gid 1505 --create-home --uid 1504 badgeblue

Update docker-compose:

    $ vim /var/lib/badgeblue/docker-compose.yml

```
version: '3.9'
services:
  badgeblue:
    labels: [ "com.centurylinklabs.watchtower.scope=badgeblue" ]
    container_name: badgeblue
    image: sjc.vultrcr.com/ngerakines/badgeblue:latest
    restart: unless-stopped
    ports:
    - "127.0.0.1:4300:4300"
    environment:
      PORT: "4300"
```

Create systemd script

    $ vim /etc/systemd/system/badgeblue.service

```
[Unit]
Description=Blue Badge
Documentation=https://badge.blue/
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/var/lib/badgeblue
ExecStart=/usr/bin/docker compose --file /var/lib/badgeblue/docker-compose.yml up --detach
ExecStop=/usr/bin/docker compose --file /var/lib/badgeblue/docker-compose.yml stop

[Install]
WantedBy=default.target
```

