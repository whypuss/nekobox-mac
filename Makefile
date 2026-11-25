VERSION ?= 1.6.1

.PHONY: all universal arm64 amd64 dmg dmg-all test clean run

all: universal

universal:
	VERSION=$(VERSION) bash scripts/build_app.sh universal

arm64:
	VERSION=$(VERSION) bash scripts/build_app.sh arm64

amd64:
	VERSION=$(VERSION) bash scripts/build_app.sh amd64

dmg:
	VERSION=$(VERSION) bash scripts/package_dmg.sh universal

dmg-all:
	VERSION=$(VERSION) bash scripts/package_dmg.sh universal
	VERSION=$(VERSION) bash scripts/package_dmg.sh arm64
	VERSION=$(VERSION) bash scripts/package_dmg.sh amd64

test:
	cd core && go test -tags "with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_v2ray_api" ./...

run: universal
	open build/Nekobox-Mac.app

clean:
	rm -rf build dist
