data_dir = "/abs/path/nomad-data"
bind_addr = "127.0.0.1"

# ES submits only with its own least-privilege token in namespace es-submit-v1.
# Without ACLs any local process could submit jobs and bypass ES admission, so
# ES refuses to submit to a Nomad that does not enforce them. Provision the
# namespace, policies and token files with scripts/internal/nomad_acl.py.
acl {
  enabled = true
}

server {
  enabled = true
  bootstrap_expect = 1
  # Gossip is encrypted with the keyring at <data_dir>/server/serf.keyring,
  # which must be in place (mode 0600) before Nomad starts: Nomad reads it
  # then, so no key appears here. scripts/70_linux_setup.sh writes it for its
  # own data_dir (/opt/nomad/es-data); for another data_dir, see the bring-up
  # runbook.
}

client {
  enabled = true
  # Nomad gives the node its host network from loopback, where it already
  # binds and advertises. ES jobs ask for no ports and need only that host
  # network to exist, and loopback exists whether the host is on Wi-Fi or a
  # cable. Without this line Nomad takes the default route's interface and
  # does not start while there is none (Wi-Fi not up yet); pinned to a wired
  # port, the node has no host network while the cable is out, and every ES
  # job fails to place ("missing network").
  network_interface = "lo"
  options = {
    "driver.allowlist" = "docker"
  }
}

# ES runs every task through its runtime helper on the Docker driver, so only
# that driver is enabled and the Docker plugin is limited (audit INF-02): no
# privileged containers, and only the capabilities the helper uses to prepare
# a run and drop to the workload user. ES's bind mounts need volumes enabled.
# Runtime profile images must survive image garbage collection.
plugin "docker" {
  config {
    allow_privileged = false
    allow_caps       = ["chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap"]

    volumes {
      enabled = true
    }

    gc {
      image = false
    }
  }
}

advertise {
  http = "127.0.0.1:4646"
  rpc  = "127.0.0.1:4647"
  serf = "127.0.0.1:4648"
}

# HTTPS and RPC over TLS 1.3 only. scripts/70_linux_setup.sh issues this
# certificate (server.global.nomad, localhost, 127.0.0.1, ::1) from a CA
# whose key it destroys after signing; ES trusts only that CA and pins the
# server key (nomad.root_ca_file, nomad.server_spki_sha256). Clients
# authenticate with ACL tokens, not certificates.
tls {
  http = true
  rpc  = true

  ca_file   = "/etc/nomad.d/tls/ca.pem"
  cert_file = "/etc/nomad.d/tls/server.pem"
  key_file  = "/etc/nomad.d/tls/server-key.pem"

  verify_server_hostname = true
  verify_https_client    = false
  tls_min_version        = "tls13"
}
