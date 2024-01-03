metatrapd
======================
A canary service for cloud metadata end-points. Quietly monitors and alerts on attempts to access the cloud metadata service.

Overview
========
Metatrapd aims to be lightweight and unintrusive. It can be used in environments where the cloud metadata service is enabled, as well as those where it has been disabled. The service is compatible with all metadata services that use http://169.254.254.169 (AWS, GCP, Azure, DigitalOcean etc).

Features
============
The primary tasks of metatrapd are to;

* log metadata requests
* alert on metadata access
* add authentication to metadata

All of these can be used in conjunction, or separately. 

Setup and Usage
============

The service can be built from source, with the easiest way to get started being:

```bash
go get github.com/staaldraad/metatrapd
```

The pre-compiled binaries can also be downloaded from the releases section.

## Verification
Pre-compiled binaries can be verified with the following public key
([minisign](https://jedisct1.github.io/minisign/)):

```
RWSQ5/CL7LMQ/YUj1KZqk4n7fMnftqJjNw3adtN3oNhEmn9HgiGEunvG
```

## Configuration

_It is recommended to run metatrapd as a stand-alone, low privileged user._

Create a user to run the binary under. This allows you to have an unprivileged service-user that only exists to run the metadata canary service. Copy the binary to a location where access it and make sure the execute bit is set.

```bash
useradd metatrapd
sudo cp metatrapd /usr/bin/metatrapd
sudo chmod +x /usr/bin/metatrapd
# allow reading of /proc/<pid>/ so we can resolve process triggering the alert
sudo setcap cap_dac_read_search,cap_sys_ptrace+eip /usr/bin/metatrapd
```

### iptables

Configure these environment variables to match your configuration:

```bash
COALMINE=127.0.0.1 # host for the canary (the canary doesn't need to run on the same host!)
COALMINE_PORT=8011 # port for the canary
```
As root (or sudo), setup the required iptables rules. 

Block all metadata access, except for an allowed user; for example the metatrapd user setup above for running the metadata proxy

```bash
MUID=$(id -u metatrapd)
# insert rather than append, to ensure we are ahead of any existing rules such as in gcp
iptables -t nat -I OUTPUT -m owner ! --uid-owner $MUID -d 169.254.169.254 -p tcp -m tcp --dport 80 -j DNAT --to-destination $COALMINE:$COALMINE_PORT
```

Alternatively, set that all traffic destined to the metadata service goes to the canary instead. This is effectively a 'log and block' rule.

```bash
iptables -t nat -I OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j DNAT --to-destination $COALMINE:$COALMINE_PORT
```

To detect attempts to access metadata from a docker container:

```bash
iptables -t nat -I PREROUTING -p tcp -d 169.254.169.254 -i docker0 -j DNAT --to-destination $COALMINE:$COALMINE_PORT
```

If you want to optionally still allow metadata access but via a different address (security by obscurity really):

```bash
iptables -t nat -I OUTPUT -p tcp -d 169.254.169.253 -j DNAT --to-destination 169.254.169.254
```


### run metatrapd

If just testing it out, simply run as the metatrapd user:

```
$ ./metatrapd -h
Usage of metatrapd:
  -allow string
        Comma seperated paths of binaries that do not trigger alerts  (eg: "/usr/bin/curl,/usr/bin/datadog")
  -auth string
        A secret value that allows requests through the proxy [XHEADER]
  -host string
        The address to listen on if not localhost (only practical in ALERT mode) (default "127.0.0.1")
  -logpath string
        Write to a custom location rather than syslog
  -mode string
        The Mode to use either PROXY or ALERT [MODE] (default "PROXY")
  -port int
        The port to listen on [COALMINE_PORT] (default 8997)
  -quiet
        Don't alert in PROXY mode when correct auth header is given
  -slackChannel string
        A slack channel to send alerts to [SLACK_CHANNEL]
  -slackToken string
        A slack token to use with channel [SLACK_TOKEN]
  -slackWebhook string
        A slack webhook to send alerts to [SLACK_WEBHOOK]
  -webhook string
        A webhook to send alerts to [WEBHOOK]
  -webhookAuth string
        An optional header to authenticate with the webhook [WEBHOOK_AUTH]
```

There are two modes, either `PROXY` or `ALERT`. In `ALERT` mode, the metadata request will be blocked and an alert will be sent. In `PROXY` mode, requests will still be **allowed** to the metadata service. There are two modes of operation under `PROXY`:

* with Auth
* no Auth

When auth is used, the requestor needs to set a specific `X-Meta-Auth` header value, if the value matches, the request is allowed through and is only logged. If the value does not match, we log, alert, and block the request. The secret is controlled through the `XHEADER` environment variable or `-auth` argument.

_If no value is set for `XHEADER`, all requests will be proxied without alerting. Requests will only be logged. An optional `-twerp` cli flag can be set to always alert regardless of the `XHEADER` being correct or not_

All logs go to stdout and syslog by default. Logs can be written to file instead of syslog by setting `-logpath` to a file location (user metatrapd must have access to write)

### As a service:

Create an environment file: `/etc/systemd/system/metatrapd.environment`

```
COALMINE_PORT=8011
MODE=PROXY
XHEADER=881122334411
SLACK_CHANNEL=C02DQA20XKK
SLACK_TOKEN=xoxb-11111-11111-22222
```

Create the service file: `/etc/systemd/system/metatrapd.service`
```
[Unit]
Description=metatrapd
After=network-online.target

[Service]
Type=exec
Restart=on-failure
User=metatrapd
CapabilityBoundingSet=cap_dac_read_search cap_sys_ptrace
AmbientCapabilities=cap_dac_read_search cap_sys_ptrace
EnvironmentFile=/etc/systemd/system/metatrapd.environment
ExecStart=/usr/bin/metatrapd

[Install]
WantedBy=multi-user.target
```

And install the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable metatrapd
sudo systemctl start metatrapd
```

## Example

Proxy mode, with secure header and always alert:

Request:
```bash
curl -H "X-Meta-Auth: pew" http://169.254.169.254/metadata/v1/
id
hostname
user-data
vendor-data
public-keys
region
interfaces/
dns/
floating_ip/
tags/
```

Metatrapd
```bash
$ XHEADER=pew ./metatrapd -port 8011
metatrapd: 2021/09/24 16:29:55 Starting metatrapd in [PROXY-mode] on 8011
metatrapd: 2021/09/24 16:31:15 Meta-data access [/metadata/v1] - [curl/7.76.1] - [fedora] - [[::1]:39272] - [/usr/bin/curl]
```

## Advanced

If you have agents such as the DataDog agent that periodically poll the metadata service, you might want to allow those agents to bypass canary. You could achieve this with the `-allow` argument:

```bash
./metatrapd -allow "/usr/bin/curl,/usr/bin/myname"
```

Alternatively, if the agent runs as a specific user, `iptables` can be used to allow the agent to bypass the canary:

```bash
AUID=$(id -u service-user) # the user the service runs as
MUID=$(id -u metatrapd)
iptables -t nat -A OUTPUT -m owner --uid-owner ${AUID} -d 169.254.169.254 -p tcp -m tcp --dport 80 -j ACCEPT
iptables -t nat -A OUTPUT -m owner --uid-owner ${MUID} -d 169.254.169.254 -p tcp -m tcp --dport 80 -j ACCEPT
iptables -t nat -A OUTPUT -d 169.254.169.254 -p tcp -m tcp --dport 80 -j DNAT --to-destination $COALMINE:$COALMINE_PORT
```

License
============
metatrapd is licensed under the Apache license, version 2.0. Full license text is available in the [LICENSE](LICENSE) file.

Please note that the project explicitly does not require a CLA (Contributor License Agreement) from its contributors.

