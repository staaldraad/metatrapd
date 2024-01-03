package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/staaldraad/metatrapd/util"
)

var config util.Config
var logger *log.Logger

// NoXForwardedTransport is used to overwrite the Transporter for httputil.ReverseProxy
type NoXForwardedTransport struct{}

// RoundTrip to remove the X-Forwarded-For header before forwarding the request. This
// is necessary as some meta-data implementations reject all requests with this header set.
// The httputil.ReverseProxy always sets the X-Forwarded-For header, with no way to disable
// this behaviour. Also delete the X-Meta-Auth header so we don't accidentally leak this
// anywhere. We still want all other headers to go through.
func (t NoXForwardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Meta-Auth")
	return http.DefaultTransport.RoundTrip(r)
}

// serveRequest will service the incoming request and respond in the same
// way as the target metadata service
func serveRequest(w http.ResponseWriter, r *http.Request) {

	// find connection owner process
	// this must be a blocking call because we need to connection to be
	// alive in order to do the resolution
	app, err := util.ResolveConnectionOwner(r.RemoteAddr)
	if err != nil {
		logger.Printf("failed to resolve connection owner; %s", err)
	}
	// log request
	go logRequest(r, app)
	if !allowedApp(app) {
		go sendAlert(r, app, "")
	}

	// serve fake metadata service
	// check if headers set for known metadata services such as GCP or Azure and serve appropriate fake data
	// not really necessary because the canary has twerped... but we can also frustrate the attacker a little
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte("200 - OK"))
	if err != nil {
		logger.Printf("failed to respond to request; %s", err)
	}
}

// serveProxy will provide a proxy to the real metadata service
// and ensure all traffic is logged
// optionally will ensure that correct X-Meta-Auth header is set
func serveProxy(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// find connection owner process
		// this must be a blocking call because we need to connection to be
		// alive in order to do the resolution
		app, err := util.ResolveConnectionOwner(r.RemoteAddr)
		if err != nil {
			logger.Printf("failed to resolve connection owner; %s", err)
		}
		xmeta := string(r.Header.Get("X-Meta-Auth"))

		// log request so we have access log of data requested from metadata
		go logRequest(r, app)

		// check if app is in the allowList
		if !allowedApp(app) {
			if config.SecureHeader != "" && xmeta != config.SecureHeader {
				// alert because this wasn't an authorized request
				go sendAlert(r, app, "Unauthorized - Bad X-Meta-Auth")

				// respond
				w.WriteHeader(http.StatusUnauthorized)
				_, err := w.Write([]byte("401 - Unauthorized"))
				if err != nil {
					logger.Printf("failed to respond to request; %s", err)
				}
				return
			}

			if !config.Quiet {
				go sendAlert(r, app, "Canary Triggered - Proxy Mode")
			}
		}
		p.ServeHTTP(w, r)
	}
}

// logRequest records details about the request being made
func logRequest(r *http.Request, app string) {
	path := r.URL.Path
	ua := r.Header.Get("User-Agent")
	hostname, _ := os.Hostname()
	src := r.RemoteAddr

	logger.Printf("Meta-data access [%s] - [%s] - [%s] - [%s] - [%s]\n", path, ua, hostname, src, app)
}

// sendAlert sends a canary alert message that the trap has been triggered
func sendAlert(r *http.Request, app, contextMessage string) {
	// will send to all configured alerting mechanisms
	alert := util.Alert{}
	alert.Path = r.URL.Path
	alert.UA = r.Header.Get("User-Agent")
	alert.Hostname, _ = os.Hostname()
	alert.Src = r.RemoteAddr
	alert.App = app
	alert.Detail = contextMessage

	if config.Slack.Webhook != "" || config.Slack.Channel != "" {
		if err := util.SlackAlert(&config.Slack, alert); err != nil {
			logger.Printf("Failed to send Slack alert; %v", err)
		}
	}

	if config.Webhook.Webhook != "" {
		if err := util.WebhookAlert(&config.Webhook, alert); err != nil {
			logger.Printf("Failed to send webhook alert; %v", err)
		}
	}
}

func allowedApp(appPath string) bool {
	for _, path := range config.AllowList {
		if path == appPath {
			return true
		}
	}
	return false
}

func initConfig() {

	var allowList string
	flag.StringVar(&config.Mode, "mode", LookupEnvOrString("MODE", config.Mode), "The Mode to use either PROXY or ALERT [MODE]")
	flag.StringVar(&config.Host, "host", LookupEnvOrString("COALMINE", config.Host), "The address to listen on if not localhost (only practical in ALERT mode)")
	flag.IntVar(&config.Port, "port", LookupEnvOrInt("COALMINE_PORT", config.Port), "The port to listen on [COALMINE_PORT]")
	flag.BoolVar(&config.Quiet, "quiet", false, "Don't alert in PROXY mode when correct auth header is given")

	flag.StringVar(&config.SecureHeader, "auth", LookupEnvOrString("XHEADER", config.SecureHeader), "A secret value that allows requests through the proxy [XHEADER]")

	flag.StringVar(&config.Slack.Webhook, "slackWebhook", LookupEnvOrString("SLACK_WEBHOOK", config.Slack.Webhook), "A slack webhook to send alerts to [SLACK_WEBHOOK]")
	flag.StringVar(&config.Slack.Channel, "slackChannel", LookupEnvOrString("SLACK_CHANNEL", config.Slack.Channel), "A slack channel to send alerts to [SLACK_CHANNEL]")
	flag.StringVar(&config.Slack.Token, "slackToken", LookupEnvOrString("SLACK_TOKEN", config.Slack.Token), "A slack token to use with channel [SLACK_TOKEN]")

	flag.StringVar(&config.Webhook.Webhook, "webhook", LookupEnvOrString("WEBHOOK", config.Webhook.Webhook), "A webhook to send alerts to [WEBHOOK]")
	flag.StringVar(&config.Webhook.WebhookAuth, "webhookAuth", LookupEnvOrString("WEBHOOOK_AUTH", config.Webhook.WebhookAuth), "An optional header to authenticate with the webhook [WEBHOOK_AUTH]")

	flag.StringVar(&config.LogFile, "logpath", "", "Write to a custom location rather than syslog")
	flag.StringVar(&allowList, "allow", LookupEnvOrString("ALLOW_LIST", ""), "Comma seperated paths of binaries that do not trigger alerts (eg: /usr/bin/curl,/usr/bin/datadog)")

	flag.Parse()

	var err error
	logger, err = util.GetLogger(config.LogFile)

	if err != nil {
		log.Fatalf("unable to set logging: %v", err)
	}

	if config.Mode != "PROXY" && config.Mode != "ALERT" {
		logger.Fatalf("invalid mode [%s]", config.Mode)
	}

	if config.Slack.Channel != "" && config.Slack.Token == "" {
		logger.Fatal("SLACK_TOKEN or -slackToken must be set when -slackChannel or SLACK_CHANNEL is set")
	}

	if allowList != "" {
		config.AllowList = strings.Split(allowList, ",")
	}
}

func main() {

	config = util.Config{
		Mode:         "PROXY",
		Host:         "127.0.0.1",
		Port:         8997,
		SecureHeader: "",
		Slack:        util.SlackConfig{},
		Webhook:      util.WebhookConfig{},
	}

	// configure via env and flag variables
	initConfig()

	if config.Mode == "PROXY" {
		realMeta := "http://169.254.169.254"
		remote, err := url.Parse(realMeta)
		if err != nil {
			panic(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(remote)
		// disable setting of x-forwarded-for
		proxy.Transport = NoXForwardedTransport{}
		http.HandleFunc("/", serveProxy(proxy))
	} else {
		http.HandleFunc("/", serveRequest)
	}

	logger.Printf("Starting metatrapd in [%s-mode] on %s:%d\n", config.Mode, config.Host, config.Port)

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", config.Host, config.Port), nil); err != nil {
		logger.Fatalf("failed to start metatrapd. %s", err)
	}
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func LookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalf("LookupEnvOrInt[%s]: %v", key, err)
		}
		return v
	}
	return defaultVal
}
