package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceVM() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceVMCreate,
		ReadContext:   resourceVMRead,
		UpdateContext: resourceVMUpdate,
		DeleteContext: resourceVMDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(1, 64),
				Description:  "VM adı (benzersiz olmalı)",
			},
			"vcpus": {
				Type:         schema.TypeInt,
				Required:     true,
				ValidateFunc: validation.IntBetween(1, 256),
				Description:  "Sanal CPU sayısı",
			},
			"memory_mb": {
				Type:         schema.TypeInt,
				Required:     true,
				ValidateFunc: validation.IntAtLeast(128),
				Description:  "RAM (MB)",
			},
			"disk_gb": {
				Type:         schema.TypeInt,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.IntAtLeast(1),
				Description:  "Disk boyutu (GB)",
			},
			"iso_path": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "ISO dosya yolu (sunucu üzerinde)",
			},
			"network": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "default",
				ForceNew:    true,
				Description: "libvirt ağ adı",
			},
			"os_variant": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "generic",
				ForceNew:    true,
				Description: "OS varyantı (virt-install --os-variant değerleri)",
			},
			"disk_format": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "qcow2",
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"qcow2", "raw"}, false),
				Description:  "Disk formatı: qcow2 veya raw",
			},
			"cloud_init_user": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "cloud-init kullanıcı adı",
			},
			"cloud_init_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "cloud-init kullanıcı şifresi",
			},
			"cloud_init_ssh_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "cloud-init SSH public key",
			},
			"cloud_init_hostname": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "cloud-init hostname",
			},
			"state": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "VM durumu (running / shut off)",
			},
			"vnc_port": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "VNC port",
			},
		},
	}
}

func resourceVMCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*OXwareClient)

	body := map[string]interface{}{
		"name":      d.Get("name").(string),
		"vcpus":     d.Get("vcpus").(int),
		"memory_mb": d.Get("memory_mb").(int),
		"disk_gb":   d.Get("disk_gb").(int),
		"network":   d.Get("network").(string),
		"os_variant": d.Get("os_variant").(string),
		"disk_format": d.Get("disk_format").(string),
	}
	if v := d.Get("iso_path").(string); v != "" {
		body["iso_path"] = v
	}

	ciUser := d.Get("cloud_init_user").(string)
	ciPass := d.Get("cloud_init_password").(string)
	ciKey  := d.Get("cloud_init_ssh_key").(string)
	ciHost := d.Get("cloud_init_hostname").(string)
	if ciUser != "" || ciPass != "" || ciKey != "" || ciHost != "" {
		body["cloud_init"] = map[string]interface{}{
			"user":     ciUser,
			"password": ciPass,
			"ssh_key":  ciKey,
			"hostname": ciHost,
		}
	}

	resp, err := c.do("POST", "/vms", body)
	if err != nil {
		return diag.FromErr(fmt.Errorf("VM oluşturulamadı: %w", err))
	}

	id, ok := resp["id"].(string)
	if !ok || id == "" {
		return diag.Errorf("API'den VM id alınamadı")
	}
	d.SetId(id)

	return resourceVMRead(ctx, d, meta)
}

func resourceVMRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*OXwareClient)

	resp, err := c.do("GET", "/vms/"+d.Id(), nil)
	if err != nil {
		d.SetId("")
		return diag.FromErr(fmt.Errorf("VM okunamadı: %w", err))
	}

	vm, _ := resp["vm"].(map[string]interface{})
	if vm == nil {
		vm = resp
	}

	_ = d.Set("name", vm["name"])
	_ = d.Set("state", vm["state"])
	if vcpus, ok := vm["vcpus"].(float64); ok {
		_ = d.Set("vcpus", int(vcpus))
	}
	if mem, ok := vm["memory_mb"].(float64); ok {
		_ = d.Set("memory_mb", int(mem))
	}
	if port, ok := vm["vnc_port"].(float64); ok {
		_ = d.Set("vnc_port", int(port))
	}

	return nil
}

func resourceVMUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*OXwareClient)

	if d.HasChanges("vcpus", "memory_mb") {
		body := map[string]interface{}{
			"vcpus":     d.Get("vcpus").(int),
			"memory_mb": d.Get("memory_mb").(int),
		}
		_, err := c.do("PUT", "/vms/"+d.Id()+"/hardware", body)
		if err != nil {
			return diag.FromErr(fmt.Errorf("VM güncellenemedi: %w", err))
		}
	}

	return resourceVMRead(ctx, d, meta)
}

func resourceVMDelete(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	c := meta.(*OXwareClient)

	_, err := c.do("DELETE", "/vms/"+d.Id(), nil)
	if err != nil {
		return diag.FromErr(fmt.Errorf("VM silinemedi: %w", err))
	}
	d.SetId("")
	return nil
}
