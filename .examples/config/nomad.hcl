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
    "docker.cleanup.image" = "false"
    "docker.volumes.enabled" = "true"
  }
}

advertise {
  http = "127.0.0.1:4646"
  rpc  = "127.0.0.1:4647"
  serf = "127.0.0.1:4648"
}
