data_dir = "/abs/path/nomad-data"
bind_addr = "127.0.0.1"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  options = {
    "docker.volumes.enabled" = "true"
  }
}
