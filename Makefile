VERSION ?= 1.6.1

.PHONY: all universal arm64 x64 amd64 dmg dmg-all test clean run

all: universal

universal:
	VERSION=$(VERSION) bash scripts/build_app.sh universal

arm64:
	VERSION=$(VERSION) bash scripts/build_app.sh arm64

x64:
	VERSION=$(VERSION) bash scripts/build_app.sh x64

amd64: x64

dmg:
	VERSION=$(VERSION) bash scripts/package_dmg.sh universal

dmg-all:
	VERSION=$(VERSION) bash scripts/package_dmg.sh arm64
	VERSION=$(VERSION) bash scripts/package_dmg.sh x64
	VERSION=$(VERSION) bash scripts/package_dmg.sh universal

test:
	cd core && go test -tags "with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_v2ray_api" -ldflags "-checklinkname=0" ./...

run: universal
	open build/Nekobox-Mac.app

clean:
	rm -rf build dist
