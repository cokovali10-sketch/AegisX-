module aegisx.local/sentinel-recon

go 1.22

require (
	aegisx/proto v0.0.0
	golang.org/x/net v0.26.0
	google.golang.org/grpc v1.64.1
	google.golang.org/protobuf v1.34.2
)

require (
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
)

replace aegisx/proto => ../proto
