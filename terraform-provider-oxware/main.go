package main

import (
	"github.com/ShinnAsukha/oxware-hypervisor/terraform-provider-oxware/internal/provider"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: provider.New,
	})
}
