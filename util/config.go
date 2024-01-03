package util

type Config struct {
	Mode         string
	Host         string // host address to listen on (default 127.0.0.1)
	Port         int
	Slack        SlackConfig   // configuration for alerting to a slack webhook
	Webhook      WebhookConfig // configuration for alerting to
	SecureHeader string        // x-meta-auth header secret
	Quiet        bool          // when true, don't alert if in proxy mode and x-meta-auth is correct
	LogFile      string        // where to write logs to
	AllowList    []string      // binaries that bypass the canary alerting and auth
}

type SlackConfig struct {
	Webhook string // webhook URL if posting to webhook
	Channel string // channel if using a bot channel
	Token   string // bot-token, must be set if channel is used
}

type WebhookConfig struct {
	Webhook     string // webhook endpoint https://myhost.com/hook
	WebhookAuth string // optional Auth header - X-Auth: <token>
}
