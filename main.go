/*
 * Filename: main.go
 * Author: Bobby Williams <bobwilliams@*****.com>
 *
 * Copyright (c) 2023
 *
 * Description: This tool creates the necessary objects in the Palo Alto firewall for a new customer VPN tunnel including IKE/IPSEC profiles, IPSEC tunnel interface and routing through the tunnel.
 * Customer details are defined in a YAML configuration file in which this tool will load.
 */
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/netw/ikegw"
	"github.com/PaloAltoNetworks/pango/netw/interface/tunnel"
	"github.com/PaloAltoNetworks/pango/netw/ipsectunnel"
	proxyipv4 "github.com/PaloAltoNetworks/pango/netw/ipsectunnel/proxyid/ipv4"
	"github.com/PaloAltoNetworks/pango/netw/profile/ike"
	"github.com/PaloAltoNetworks/pango/netw/profile/ipsec"
	"github.com/PaloAltoNetworks/pango/netw/routing/route/static/ipv4"
	"github.com/PaloAltoNetworks/pango/netw/zone"
	"github.com/PaloAltoNetworks/pango/objs/addr"
	"github.com/howeyc/gopass"
	yaml "gopkg.in/yaml.v3"
)

const (
	testFW         = "palo-test-fw01.******.com"
	prodFW         = "palo-prod-fw1.******.com"
	vsys           = "vsys1"
	fwCommitCmd    = "<commit></commit>"
	testOctet      = "215"
	prodOctet      = "216"
	testVR         = "default-vr"
	prodVR         = "default"
	testOutsideInt = "ethernet1/1"
	prodOutsideInt = "ethernet1/2"
)

var (
	user, pass string // Firewall credentials
	env        string // Firewall environment
	fwHostname string // Firewall Hostname (depending on environment passed in)
	octet      string // Environment octect (ex. test = 10.<octet>.2.<tunnel_number)
	vr         string // Virtual router name (for the PAN routing table)
	outsideInt string // Outside interface
)

// Represents a client's configuration
type clientConfig struct {
	Name          string `yaml:"client_name"`
	Tunnel        string `yaml:"tunnel_number"`
	PublicIP      string `yaml:"client_public_ip"`
	RemoteCIDR    string `yaml:"client_remote_host_cidr"`
	Phase1Enc     string `yaml:"phase1_encryption"`
	Phase1Auth    string `yaml:"phase1_authentication"`
	Phase1DH      string `yaml:"phase1_dh_group"`
	Phase1LTType  string `yaml:"phase1_lifetime_type"`
	Phase1LTValue int    `yaml:"phase1_lifetime_value"`
	Phase2Enc     string `yaml:"phase2_encryption"`
	Phase2Auth    string `yaml:"phase2_authentication"`
	Phase2DH      string `yaml:"phase2_dh_group"`
	Phase2LTType  string `yaml:"phase2_lifetime_type"`
	Phase2LTValue int    `yaml:"phase2_lifetime_value"`
	PreSharedKey  string `yaml:"pre_shared_key"`
}

func main() {
	// Load client configuration file
	config := flag.String("c", "", "Client config file")
	flag.StringVar(&env, "e", env, "Firewall environment (test, prod)")
	flag.Parse()

	// Check for flags not being set
	switch {
	case *config == "":
		fmt.Fprintln(os.Stderr, "Config file not found, exiting..")
		flag.Usage()
		os.Exit(1)
	case env == "":
		fmt.Fprintln(os.Stderr, "Environment not set, exiting..")
		flag.Usage()
		os.Exit(1)
	}
	// Determine which firewall to configure
	switch env {
	case "test":
		fwHostname = testFW
		octet = testOctet
		vr = testVR
		outsideInt = testOutsideInt
	case "prod":
		fwHostname = prodFW
		octet = prodOctet
		vr = prodVR
		outsideInt = prodOutsideInt
	default:
		fmt.Fprintln(os.Stderr, "No such firewall environment.")
		flag.Usage()
		os.Exit(1)
	}

	// Load configurtion file
	configBytes, err := os.ReadFile(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Convert YAML to struct(s)
	var clients []clientConfig
	if err = yaml.Unmarshal(configBytes, &clients); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Get user's firewall credentials
	getCreds()

	// Create firewall client & Initialize it
	fw := pango.Firewall{
		Client: pango.Client{
			Hostname: fwHostname,
			Username: user,
			Password: pass,
		},
	}
	if err = fw.Initialize(); err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Unable to initialize %s firewall - check your credentials.", env))
		os.Exit(1)
	}
	// Process each client found in the configuration file
	for _, client := range clients {
		// Create client objects
		fmt.Printf("Attempting to create client '%v' objects..\n", client.Name)
		if err := createClientObjs(&fw, client); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else {
			fmt.Printf("%v's objects created successfully!\n", client.Name)
		}

		// Create client zone and tunnel interface
		fmt.Printf("Attempting to create client '%v' tunnel interface and zone..\n", client.Name)
		if err := createZoneAndInterface(&fw, client); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else {
			fmt.Printf("%v's, tunnel interface and zone created successfully!\n", client.Name)
		}

		// Create client ike & ipsec profiles
		fmt.Printf("Attempting to create client '%v' ike & ipsec profiles..\n", client.Name)
		if err := createIkeAndIpsecProfiles(&fw, client); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else {
			fmt.Printf("'%v's, ike & ipsec profiles created successfully!\n", client.Name)
		}

		// Create client static route
		fmt.Printf("Attempting to create client '%v' static route..\n", client.Name)
		if err := createStaticRoute(&fw, client); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else {
			fmt.Printf("%v's, static route created successfully!\n", client.Name)
		}

		// Create IPSEC Tunnel
		fmt.Printf("Attempting to create client '%v' IPSEC tunnel..\n", client.Name)
		if err := createIpsecTunnel(&fw, client); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		} else {
			fmt.Printf("%v's, IPSEC tunnel created successfully!\n", client.Name)
		}

	}

	// Commit changes
	fmt.Println("Attempting to commit changes..")
	jobID, _, err := fw.Commit(fwCommitCmd, "", nil)
	if err == nil {
		fmt.Println("Changes committed successfully! | Job Id:", jobID)
		return
	} else {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Failed at commting changes: %v", err))
		os.Exit(1)
	}
	cleanExit()
}

// Create IPSEC Tunnel
func createIpsecTunnel(fw *pango.Firewall, c clientConfig) error {
	err := fw.Network.IpsecTunnel.Set(ipsectunnel.Entry{
		Name:                 fmt.Sprintf("%v-tunnel", c.Name),
		TunnelInterface:      fmt.Sprintf("tunnel.%v", c.Tunnel),
		Type:                 "auto-key",
		AkIkeGateway:         fmt.Sprintf("%v-%v", c.Name, env),
		AkIpsecCryptoProfile: fmt.Sprintf("%v-phase2-crypto", c.Name),
	})
	if err != nil {
		return err
	}

	err = fw.Network.IpsecTunnelProxyId.Set(fmt.Sprintf("%v-tunnel", c.Name), proxyipv4.Entry{
		Name:        fmt.Sprintf("proxy-%v", c.Tunnel),
		Local:       fmt.Sprintf("10.%v.2.0/24", octet),
		Remote:      c.RemoteCIDR,
		ProtocolAny: true,
	})
	if err != nil {
		return err
	}
	return nil
}

// Create Static Route
func createStaticRoute(fw *pango.Firewall, c clientConfig) error {
	err := fw.Network.StaticRoute.Set(vr, ipv4.Entry{
		Name:        fmt.Sprintf("%v-%v", c.Name, strings.Split(c.RemoteCIDR, "/")[0]),
		Destination: fmt.Sprintf("%v-remote-host-%v", c.Name, strings.Split(c.RemoteCIDR, "/")[0]),
		Interface:   fmt.Sprintf("tunnel.%v", c.Tunnel),
	})
	if err != nil {
		return err
	}
	return nil
}

// Create client IKE and IPSEC profiles
func createIkeAndIpsecProfiles(fw *pango.Firewall, c clientConfig) error {
	// Create IKE profile
	err := fw.Network.IkeCryptoProfile.Set(ike.Entry{
		Name:           fmt.Sprintf("%v-phase1-crypto", c.Name),
		DhGroup:        []string{"group" + c.Phase1DH},
		Authentication: []string{c.Phase1Auth},
		Encryption:     []string{c.Phase1Enc},
		LifetimeType:   c.Phase1LTType,
		LifetimeValue:  c.Phase1LTValue,
	})
	if err != nil {
		return err
	}
	// Create IPSEC profile
	err = fw.Network.IpsecCryptoProfile.Set(ipsec.Entry{
		Name:           fmt.Sprintf("%v-phase2-crypto", c.Name),
		Protocol:       ipsec.ProtocolEsp,
		DhGroup:        "group" + c.Phase2DH,
		Authentication: []string{c.Phase2Auth},
		Encryption:     []string{c.Phase2Enc},
		LifetimeType:   c.Phase2LTType,
		LifetimeValue:  c.Phase2LTValue,
	})
	if err != nil {
		return err
	}
	// Create IKE Gateway
	err = fw.Network.IkeGateway.Set(ikegw.Entry{
		Name:                fmt.Sprintf("%v-%v", c.Name, env),
		Version:             "ikev2",
		Interface:           outsideInt,
		PeerIpType:          "ip",
		PeerIpValue:         fmt.Sprintf("%v-peer-%v-%v", c.Name, env, c.PublicIP),
		LocalIpAddressType:  "ip",
		LocalIpAddressValue: fmt.Sprintf("outside-int-10.%v.1.10-24", octet),
		Ikev2CryptoProfile:  fmt.Sprintf("%v-phase1-crypto", c.Name),
		AuthType:            "pre-shared-key",
		PreSharedKey:        c.PreSharedKey,
	})
	if err != nil {
		return err
	}
	return nil
}

// Create client zone and interface
func createZoneAndInterface(fw *pango.Firewall, c clientConfig) error {
	zoneName := fmt.Sprintf("%v-vpn-tunnel", c.Name)
	tunnelInt := fmt.Sprintf("tunnel.%v", c.Tunnel)

	// Create tunnel interface
	err := fw.Network.TunnelInterface.Set(vsys, tunnel.Entry{Name: tunnelInt})
	if err != nil {
		return err
	}
	// Create zone
	err = fw.Network.Zone.Set(vsys, zone.Entry{Name: zoneName, Interfaces: []string{tunnelInt}})
	if err != nil {
		return err
	}
	// Assign tunnel interface to created zone
	err = fw.Network.Zone.SetInterface(vsys, zoneName, zone.ModeL3, tunnelInt)
	if err != nil {
		return err
	}
	// Assign tunnel interface to virtual router
	err = fw.Network.VirtualRouter.SetInterface(vr, tunnelInt)
	if err != nil {
		return err
	}
	return nil
}

// Creates client objects
func createClientObjs(fw *pango.Firewall, c clientConfig) error {
	objects := []addr.Entry{
		// NAT Object
		{
			Name:  fmt.Sprintf("%v-nat-10.%v.2.%v", c.Name, octet, c.Tunnel),
			Value: fmt.Sprintf("10.%v.2.%v", octet, c.Tunnel),
			Type:  addr.IpNetmask,
		},
		// Client Peer Object
		{
			Name:  fmt.Sprintf("%v-peer-%v-%v", c.Name, env, c.PublicIP),
			Value: c.PublicIP,
			Type:  addr.IpNetmask,
		},
		// Client Remote Host Object
		{
			Name:  fmt.Sprintf("%v-remote-host-%v", c.Name, strings.Split(c.RemoteCIDR, "/")[0]),
			Value: c.RemoteCIDR,
			Type:  addr.IpNetmask,
		},
	}
	return fw.Objects.Address.Set(vsys, objects...)
}

// Asks the user for their firewall credentials
func getCreds() {
	s := bufio.NewScanner(os.Stdin)
	fmt.Print("Username: ")
	if !s.Scan() {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Unable to process username: %v", s.Err()))
	} else {
		user = s.Text()
	}

	passwd, err := gopass.GetPasswdPrompt("Password: ", true, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("Unable to process password: %v", err))
		os.Exit(1)
	}
	pass = string(passwd)
}

// Exits cleanly
func cleanExit() {
	s := bufio.NewScanner(os.Stdin)
	fmt.Println("Press enter to exit.")
	s.Scan()
	os.Exit(0)
}
