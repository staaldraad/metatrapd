package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/slack-go/slack"
)

type Alert struct {
	Hostname string // hostname this occurred on
	Path     string // the path requested
	UA       string // user-agent of the request
	App      string // the resolved path to the binary making the request
	Detail   string // additional information
	Src      string // the source address (docker container, localhost, remote)
}

func SlackAlert(config *SlackConfig, alert Alert) error {
	if config.Webhook != "" {
		return slackWebhookAlert(config.Webhook, alert)
	}
	return slackChannelAlert(config.Channel, config.Token, alert)
}

func WebhookAlert(config *WebhookConfig, alert Alert) error {
	message, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	client := &http.Client{}
	req, _ := http.NewRequest("POST", config.Webhook, bytes.NewBuffer(message))
	if config.WebhookAuth != "" {
		h := strings.Split(config.WebhookAuth, ":")
		if len(h) != 2 {
			return fmt.Errorf("Invalid authorization header. Need headername:value")
		}
		req.Header.Set(h[0], h[1])
	}
	resp, err := client.Do(req)
	if err == nil {
		logger.Printf("Alert sent to webhook. Status: %d", resp.StatusCode)
	}
	return err
}

func slackWebhookAlert(webhookURL string, alert Alert) error {
	detail := ""
	if alert.Detail != "" {
		detail = fmt.Sprintf("\n:speech_balloon: *Detail:* %s", alert.Detail)
	}
	message := fmt.Sprintf(":computer: *Hostname:* %s\n:dart: *Path:* %s\n:memo: *User-Agent:* %s\n:calling: *SourceAddr:* %s\n*AppPath*: %s%s", alert.Hostname, alert.Path, alert.UA, alert.Src, alert.App, detail)

	attachment := slack.Attachment{
		Color:      "danger",
		Fallback:   "A metadata canary triggered!",
		AuthorName: "metatrapd",
		Text:       message,
		Footer:     "metatrapd",
		Ts:         json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
	}
	msg := slack.WebhookMessage{
		Text:        ":rotating_light::bird:  A metadata canary triggered!",
		Attachments: []slack.Attachment{attachment},
	}

	err := slack.PostWebhook(webhookURL, &msg)
	if err == nil {
		logger.Print("Alert sent to Slack Webhook")
	}
	return err
}

func slackChannelAlert(channel, token string, alert Alert) error {
	detail := ""
	if alert.Detail != "" {
		detail = fmt.Sprintf("\n:speech_balloon: *Detail:* %s", alert.Detail)
	}
	message := fmt.Sprintf(":computer: *Hostname:* %s\n:dart: *Path:* %s\n:memo: *User-Agent:* %s\n:calling: *Source:* %s\n*AppPath*: %s%s", alert.Hostname, alert.Path, alert.UA, alert.Src, alert.App, detail)

	api := slack.New(token)
	attachment := slack.Attachment{
		Color:      "danger",
		Fallback:   "A metadata canary triggered!",
		AuthorName: "metatrapd",
		Text:       message,
		Footer:     "metatrapd",
		Ts:         json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
	}

	channelID, _, err := api.PostMessage(
		channel,
		slack.MsgOptionText(":rotating_light::bird:  A metadata canary triggered!", false),
		slack.MsgOptionAttachments(attachment),
	)

	if err == nil {
		logger.Printf("Alert sent to Slack channel %s", channelID)
	}
	return err

}
