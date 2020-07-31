package newrelic

import (
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/newrelic/newrelic-client-go/pkg/alerts"
)

func expandAlertChannel(d *schema.ResourceData) (*alerts.Channel, error) {
	channel := alerts.Channel{
		Name: d.Get("name").(string),
		Type: alerts.ChannelType(d.Get("type").(string)),
	}

	config, configOk := d.GetOk("config")

	if !configOk {
		return nil, errors.New("alert channel requires a config or configuration attribute")
	}

	if configOk {
		var channelConfig map[string]interface{}

		x := config.([]interface{})
		if len(x) > 0 {
			if x[0] != nil {
				channelConfig = x[0].(map[string]interface{})
			}
		}

		c, err := expandAlertChannelConfiguration(channelConfig)
		if err != nil {
			return nil, err
		}

		channel.Configuration = *c
	}

	err := validateChannelConfiguration(channel.Configuration)
	if err != nil {
		return nil, err
	}

	return &channel, nil
}

//nolint:gocyclo
func expandAlertChannelConfiguration(cfg map[string]interface{}) (*alerts.ChannelConfiguration, error) {
	config := alerts.ChannelConfiguration{}

	if apiKey, ok := cfg["api_key"]; ok {
		config.APIKey = apiKey.(string)
	}

	if authPassword, ok := cfg["auth_password"]; ok {
		config.AuthPassword = authPassword.(string)
	}

	if authUsername, ok := cfg["auth_username"]; ok {
		config.AuthUsername = authUsername.(string)
	}

	if baseURL, ok := cfg["base_url"]; ok {
		config.BaseURL = baseURL.(string)
	}

	if channel, ok := cfg["channel"]; ok {
		config.Channel = channel.(string)
	}

	if key, ok := cfg["key"]; ok {
		config.Key = key.(string)
	}

	if headers, ok := cfg["headers"]; ok {
		h := headers.(map[string]interface{})
		config.Headers = h
	}

	if headers, ok := cfg["headers_string"]; ok && headers != "" {
		s := []byte(headers.(string))
		var h map[string]interface{}
		err := json.Unmarshal(s, &h)

		if err != nil {
			return nil, err
		}

		config.Headers = h
	}

	if includeJSONAttachment, ok := cfg["include_json_attachment"]; ok {
		config.IncludeJSONAttachment = includeJSONAttachment.(string)
	}

	if payload, ok := cfg["payload"]; ok {
		p := payload.(map[string]interface{})
		config.Payload = p
	}

	if payload, ok := cfg["payload_string"]; ok && payload != "" {
		s := []byte(payload.(string))
		var p map[string]interface{}
		err := json.Unmarshal(s, &p)

		if err != nil {
			return nil, err
		}

		config.Payload = p
	}

	if payloadType, ok := cfg["payload_type"]; ok {
		config.PayloadType = payloadType.(string)
	}

	if recipients, ok := cfg["recipients"]; ok {
		config.Recipients = recipients.(string)
	}

	if region, ok := cfg["region"]; ok {
		config.Region = region.(string)
	}

	if routeKey, ok := cfg["route_key"]; ok {
		config.RouteKey = routeKey.(string)
	}

	if serviceKey, ok := cfg["service_key"]; ok {
		config.ServiceKey = serviceKey.(string)
	}

	if tags, ok := cfg["tags"]; ok {
		config.Tags = tags.(string)
	}

	if teams, ok := cfg["teams"]; ok {
		config.Teams = teams.(string)
	}

	if url, ok := cfg["url"]; ok {
		config.URL = url.(string)
	}

	if userID, ok := cfg["user_id"]; ok {
		config.UserID = userID.(string)
	}

	return &config, nil
}

func expandAlertChannelIDs(channelIDs []interface{}) []int {
	ids := make([]int, len(channelIDs))

	for i := range ids {
		ids[i] = channelIDs[i].(int)
	}

	return ids
}

func flattenAlertChannelDataSource(channel *alerts.Channel, d *schema.ResourceData) error {
	d.SetId(strconv.Itoa(channel.ID))
	d.Set("policy_ids", channel.Links.PolicyIDs)

	return flattenAlertChannel(channel, d)
}

func flattenAlertChannel(channel *alerts.Channel, d *schema.ResourceData) error {
	d.Set("name", channel.Name)
	d.Set("type", channel.Type)

	config, err := flattenAlertChannelConfiguration(&channel.Configuration, d)
	if err != nil {
		return err
	}

	if err := d.Set("config", config); err != nil {
		return err
	}

	return nil
}

func flattenAlertChannelConfiguration(c *alerts.ChannelConfiguration, d *schema.ResourceData) ([]interface{}, error) {
	if c == nil {
		return nil, nil
	}

	configResult := make(map[string]interface{})

	// Conditionally sets some values the API deems sensitive
	// on the configResult map based on what the user
	// supplied in their config HCL.
	setSensitiveConfigValues(configResult, c, d)

	configResult["auth_username"] = c.AuthUsername
	configResult["base_url"] = c.BaseURL
	configResult["channel"] = c.Channel
	configResult["include_json_attachment"] = c.IncludeJSONAttachment
	configResult["payload_type"] = c.PayloadType
	configResult["recipients"] = c.Recipients
	configResult["region"] = c.Region
	configResult["route_key"] = c.RouteKey
	configResult["tags"] = c.Tags
	configResult["teams"] = c.Teams
	configResult["user_id"] = c.UserID

	// Use the current state to detect if an import
	// is being attempted.
	state := d.State()

	// An empty config means TF doesn't know about it yet because
	// at least one config attribute is required for a given channel type.
	isImportState := len(state.Attributes["config"]) == 0

	headersString, headersStringOk := d.GetOk("config.0.header_string")
	_, payloadStringOk := d.GetOk("config.0.payload_string")

	headers, headersOk := d.GetOk("config.0.headers")
	_, _ = d.GetOk("config.0.payload")

	log.Print("\n\n **************************** \n")
	log.Printf("\n IS IMPORT:       %+v  \n", isImportState)
	log.Printf("\n HEADER STRING:   %+v - %+v - %+v \n", headersString, headersStringOk, c.Headers)
	// log.Printf("\n PAYLOAD STRING:  %+v - %+v - %+v \n", payloadString, payloadStringOk, c.Payload)
	log.Print("\n **************************** \n")
	log.Printf("\n IS IMPORT:  %+v  \n", isImportState)
	log.Printf("\n HEADER:     %+v - %+v \n", headers, headersOk)
	// log.Printf("\n PAYLOAD:    %+v - %+v \n", payload, payloadOk)
	log.Print("\n **************************** \n\n")
	time.Sleep(7 * time.Second)

	// if headersOk && !headersStringOk

	if _, ok := d.GetOk("config.0.headers"); ok || isImportState && !headersStringOk {
		configResult["headers"] = c.Headers
	} else if _, ok := d.GetOk("config.0.headers_string"); ok {
		h, err := json.Marshal(c.Headers)

		if err != nil {
			return nil, err
		}

		configResult["headers_string"] = string(h)
	}

	if _, ok := d.GetOk("config.0.payload"); ok || isImportState && !payloadStringOk {
		configResult["payload"] = c.Payload
	} else if _, ok := d.GetOk("config.0.payload_string"); ok || isImportState {
		h, err := json.Marshal(c.Payload)

		if err != nil {
			return nil, err
		}

		configResult["payload_string"] = string(h)
	}

	return []interface{}{configResult}, nil
}

func validateChannelConfiguration(config alerts.ChannelConfiguration) error {
	if len(config.Payload) != 0 && config.PayloadType == "" {
		return errors.New("payload_type is required when using payload")
	}

	return nil
}

// The Rest API treats these fields as sensitive and does NOT
// return them as part of the GET response.
func setSensitiveConfigValues(
	configResult map[string]interface{},
	c *alerts.ChannelConfiguration,
	d *schema.ResourceData,
) {
	if attr, ok := d.GetOk("config.0.auth_password"); ok {
		if c.AuthPassword != "" {
			configResult["auth_password"] = c.AuthPassword
		} else {
			configResult["auth_password"] = attr.(string)
		}
	}

	if attr, ok := d.GetOk("config.0.api_key"); ok {
		if c.APIKey != "" {
			configResult["api_key"] = c.APIKey
		} else {
			configResult["api_key"] = attr.(string)
		}
	}

	if attr, ok := d.GetOk("config.0.url"); ok {
		if c.URL != "" {
			configResult["url"] = c.URL
		} else {
			configResult["url"] = attr.(string)
		}
	}

	if attr, ok := d.GetOk("config.0.key"); ok {
		if c.Key != "" {
			configResult["key"] = c.Key
		} else {
			configResult["key"] = attr.(string)
		}
	}

	if attr, ok := d.GetOk("config.0.service_key"); ok {
		if c.ServiceKey != "" {
			configResult["service_key"] = c.ServiceKey
		} else {
			configResult["service_key"] = attr.(string)
		}
	}
}
