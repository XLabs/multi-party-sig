.PHONY: proto

proto: 
	@echo "--> Building Protocol Buffers"
	@for protocol in frost-signing frost-keygen cmp-keygen cmp-signing; do \
		echo "Generating $$protocol.pb.go" ; \
		protoc --go_out=. ./proto/$$protocol.proto ; \
	done
