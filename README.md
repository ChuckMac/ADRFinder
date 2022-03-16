#  ADRFinder
[![License][license-shield]](LICENSE.md)

![ADRFinder](https://github.com/chuckmac/adrfinder/actions/workflows/test-only.yml/badge.svg?branch=master)

## Self-Hosted, Open Source, Advanced Dining Reservation Notifications for Disney World

Get a notification when those those hard to find dining reservations beceome available at Walt Disney World.

<img src="https://raw.githubusercontent.com/chuckmac/adrfinder/master/screenshot.png" style="max-width:100%;" alt="Self-hosted reservation finder"  title="Self-hosted reservation finder"  />


## Installation

### Docker

With Docker composer, just clone this repository and..
```bash
$ docker-compose up -d
```
Docker standalone
```bash
$ docker build -t adrfinder .
$ docker run -d --restart always -p "127.0.0.1:5500:5500" -v datastore-volume:/datastore --name adrfinder adrfinder
```

## Updating

### docker-compose

```bash
docker-compose pull && docker-compose up -d
```

## Notifications

ADRFinder supports a massive amount of notifications (including email, office365, custom APIs, etc) when a web-page has a change detected thanks to the <a href="https://github.com/caronc/apprise">apprise</a> library.
Simply set one or more notification URL's in the _[edit]_ tab of that watch.

Just some examples

    discord://webhook_id/webhook_token
    flock://app_token/g:channel_id
    gitter://token/room
    gchat://workspace/key/token
    msteams://TokenA/TokenB/TokenC/
    o365://TenantID:AccountEmail/ClientID/ClientSecret/TargetEmail
    rocket://user:password@hostname/#Channel
    mailto://user:pass@example.com?to=receivingAddress@example.com
    json://someserver.com/custom-api
    syslog://
 
<a href="https://github.com/caronc/apprise#popular-notification-services">And everything else in this list!</a>

<img src="https://raw.githubusercontent.com/chuckmac/adrfinder/master/screenshot-notifications.png" style="max-width:100%;" alt="Self-hosted reservation notifications"  title="Self-hosted reservation monitoring notifications"  />


You can also customise your notification content!

## Special Thanks

Special thanks to dgtlmoon's <a href="https://github.com/dgtlmoon/changedetection.io">Change Detection</a> whom much work for this project was taken from.

