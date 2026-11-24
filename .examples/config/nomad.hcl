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
}

client {
  enabled = true
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
