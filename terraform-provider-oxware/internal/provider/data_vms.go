package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceVMs() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceVMsRead,
		Schema: map[string]*schema.Schema{
			"vms": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id":        {Type: schema.TypeString, Computed: true},
						"name":      {Type: schema.TypeString, Computed: true},
						"state":     {Type: schema.TypeString, Computed: true},
						"vcpus":     {Type: schema.TypeInt, Computed: true},
						"memory_mb": {Type: schema.TypeInt, Computed: true},
						"vnc_port":  {Type: schema.TypeInt, Computed: true},
					},
				},
			},
		},
	}
}

func dataSourceVMsRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*OXwareClient)

	resp, err := c.do("GET", "/vms", nil)
	if err != nil {
		return diag.FromErr(err)
	}

	rawVMs, _ := resp["vms"].([]interface{})
	vms := make([]map[string]interface{}, 0, len(rawVMs))
	for _, v := range rawVMs {
		vm, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		entry := map[string]interface{}{
			"id":    vm["id"],
			"name":  vm["name"],
			"state": vm["state"],
		}
		if vcpus, ok := vm["vcpus"].(float64); ok {
			entry["vcpus"] = int(vcpus)
		}
		if mem, ok := vm["memory_mb"].(float64); ok {
			entry["memory_mb"] = int(mem)
		}
		if port, ok := vm["vnc_port"].(float64); ok {
			entry["vnc_port"] = int(port)
		}
		vms = append(vms, entry)
	}

	_ = d.Set("vms", vms)
	d.SetId("oxware-vms")
	return nil
}
