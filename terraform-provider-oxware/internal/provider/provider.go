package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// OXwareClient holds connection details for API calls.
type OXwareClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c *OXwareClient) do(method, path string, body interface{}) (map[string]interface{}, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+"/api"+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(raw))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("JSON parse hatası: %w", err)
	}
	return result, nil
}

// New returns the OXware Terraform provider.
func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("OXWARE_URL", nil),
				Description: "OXware Hypervisor URL (örn. https://oxware.example.com)",
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("OXWARE_TOKEN", nil),
				Description: "OXware JWT erişim token'ı",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"oxware_vm": resourceVM(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"oxware_vms": dataSourceVMs(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(_ context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	client := &OXwareClient{
		BaseURL: d.Get("url").(string),
		Token:   d.Get("token").(string),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
	return client, nil
}
