# 09: gRPC / XHTTP transport verification

**What to build:** Phase-2 config parsing and xray config generation extended
from ws-only to also accept grpc and xhttp (splithttp) transports in
vless/vmess/trojan/ss URIs (`type=grpc`, `type=xhttp`), including their
params (serviceName/`grpc-service-name`, path, host). Xray outbound config
emits the right transport settings; verification unchanged. HTTPUpgrade left
to a decision inside this ticket (parse-only vs verify).

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] `configs::parse_uri` populates grpc/xhttp transport fields
- [ ] xray config builder emits grpc/xhttp outbound transport blocks
- [ ] sing-box/clash export map the new transports or reject cleanly
- [ ] Round-trip tests: parse → xray JSON → reparse
