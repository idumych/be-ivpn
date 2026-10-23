module gocheck

go 1.26.0

require github.com/ivpn/desktop-app/daemon v0.0.0

// Point these at a checkout of https://github.com/ivpn/desktop-app
replace github.com/ivpn/desktop-app/daemon => ../../../desktop-app/daemon

replace github.com/ivpn/desktop-app/daemon/protocol/ivpnclient => ../../../desktop-app/daemon/protocol/ivpnclient
