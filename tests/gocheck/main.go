// Cross-check: our JSON must decode into the real daemon's Go types with no
// unknown fields. Run with IVPN_DAEMON_SRC=<desktop-app/daemon>.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ivpn/desktop-app/daemon/protocol/ivpnclient"

	"github.com/ivpn/desktop-app/daemon/protocol/types"
)

func strict(file string, v interface{}) {
	data, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fmt.Printf("FAIL %s: %v\n", file, err)
		os.Exit(1)
	}
}

func main() {
	byCommand := map[string]func() interface{}{
		"Disconnect":          func() interface{} { return &types.Disconnect{} },
		"GetVPNState":         func() interface{} { return &types.GetVPNState{} },
		"SessionNew":          func() interface{} { return &types.SessionNew{} },
		"SessionDelete":       func() interface{} { return &types.SessionDelete{} },
		"SessionStatus":       func() interface{} { return &types.SessionStatus{} },
		"KillSwitchSetEnabled": func() interface{} { return &types.KillSwitchSetEnabled{} },
		"KillSwitchGetStatus": func() interface{} { return &types.KillSwitchGetStatus{} },
		"PingServers":         func() interface{} { return &types.PingServers{} },
		"GetServers":          func() interface{} { return &types.GetServers{} },
	}
	for _, f := range os.Args[1:] {
		if strings.Contains(f, "req_") {
			data, _ := os.ReadFile(f)
			var base struct{ Command string }
			json.Unmarshal(data, &base)
			mk, ok := byCommand[base.Command]
			if !ok {
				fmt.Printf("FAIL %s: no Go type registered for %q\n", f, base.Command)
				os.Exit(1)
			}
			v := mk()
			strict(f, v)
			fmt.Printf("OK %s: %+v\n", base.Command, v)
			continue
		}
		if strings.Contains(f, "hello") {
			var h ivpnclient.Hello
			strict(f, &h)
			fmt.Printf("OK %s: Hello secret=%x client=%d version=%q servers=%v status=%v\n", f, h.Secret, h.ClientType, h.Version, h.GetServersList, h.GetStatus)
			continue
		}
		var req types.Connect
		strict(f, &req)
		p := req.Params
		if p.VpnType.String() == "WireGuard" {
			if len(p.WireGuardParameters.EntryVpnServer.Hosts) == 0 || p.WireGuardParameters.EntryVpnServer.Hosts[0].PublicKey == "" {
				fmt.Println("FAIL: WG hosts lost in decoding")
				os.Exit(1)
			}
			fmt.Printf("OK %s: WireGuard host=%s port=%d sel=%d\n", f, p.WireGuardParameters.EntryVpnServer.Hosts[0].Hostname, p.WireGuardParameters.Port.Port, p.Metadata.ServerSelectionEntry)
		} else {
			if len(p.OpenVpnParameters.EntryVpnServer.Hosts) == 0 {
				fmt.Println("FAIL: OpenVPN hosts lost")
				os.Exit(1)
			}
			fmt.Printf("OK %s: OpenVPN host=%s port=%d proto=%d\n", f, p.OpenVpnParameters.EntryVpnServer.Hosts[0].Hostname, p.OpenVpnParameters.Port.Port, p.OpenVpnParameters.Port.Protocol)
		}
	}
}
