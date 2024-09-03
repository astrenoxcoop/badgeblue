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

Create caddy config:

```
badge.blue {
	handle /.well-known/traffic-advice {
		header Content-Type "application/trafficadvice+json"
		respond "[{\"user_agent\": \"prefetch-proxy\", \"disallow\": true}]" 200
	}

	handle /static* {
		root * /var/lib/badgeblue/www
		file_server
	}

	@root_assets path /favicon.ico /robots.txt /humans.txt /apple-touch-icon.png /apple-touch-icon-precomposed.png /apple-touch-icon-120x120.png /apple-touch-icon-120x120-precomposed.png /icon.webp
	handle @root_assets {
		root * /var/lib/badgeblue/www/static
		file_server
	}

	handle /render* {
		route {
			uri strip_prefix /render
			redir https://render.badge.blue{uri}
		}
	}

	@app_uris path / /verify /language
	handle @app_uris {
		reverse_proxy http://127.0.0.1:4300
	}

	respond 404

	log {
		output file /var/log/caddy/badge-blue.log {
			roll_size 100Mib
			roll_keep 100
			roll_keep_for 4383h
		}
	}
}

# The origin host for the CDN that is mapped to render.badge.blue
ebcee731f1b902.badge.blue {
	handle /robots.txt {
		header Cache-Control max-age=604800
		respond <<ROBOTS
		User-agent: *
		Disallow: /
		ROBOTS 200
	}
	handle {
		rewrite * /render{path}
		reverse_proxy http://127.0.0.1:4300
	}

	respond 404

	log {
		output file /var/log/caddy/render-origin-badge-blue.log {
			roll_size 100Mib
			roll_keep 100
			roll_keep_for 4383h
		}
	}
}
```
