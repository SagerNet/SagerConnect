package tun

import "github.com/sagernet/sagerconnect/core"

func AddRoute(name string, bypassLan bool) (cmd string, err error) {
	cmd, err = core.ExecShell(cmd, err, "ifconfig", name, PrivateVlan4Client, "172.19.0.3", "netmask", "255")
	cmd, err = core.ExecShell(cmd, err, "ifconfig", name, "inet6", PrivateVlan6Client, "prefixlen", "126")
	if bypassLan {
		for _, addr := range BypassPrivateRoute {
			cmd, err = core.ExecShell(cmd, err, "route", "add", addr, "-interface", name)
		}
	} else {
		_, _ = core.ExecShell(cmd, err, "route", "delete", "default")
		cmd, err = core.ExecShell(cmd, err, "route", "add", "default", "-interface", name)
	}

	cmd, err = core.ExecShell(cmd, err, "route", "add", "-inet6", "default", "-interface", name)
	return
}
