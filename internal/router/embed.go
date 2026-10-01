package router

import _ "embed"

// embeddedCNIP is the mainland China prefix list, compiled in so the client can
// set up split routing without network access to GitHub.
//
// Refresh it from https://github.com/17mon/china_ip_list when prefixes change;
// a stale list sends a few domestic destinations through the tunnel, which costs
// latency but still works. Configuring routing.cnip_file overrides this copy.
//
//go:embed data/chnroute.txt
var embeddedCNIP string
