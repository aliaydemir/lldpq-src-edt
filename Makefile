# LLDPq test entrypoint. Test deps: pytest, pyyaml, requests, jinja2, ruamel.yaml
# (install them in whatever python3 environment is on PATH; no venv is assumed).
# The node test legs use the built-in node:test runner and require Node >= 18.

.PHONY: test lint

test:
	python3 -m pytest lldpq/ -q
	node --test lldpq/test_*.mjs
	@# bash -n sweep over every bash file, sourced ones without a shebang included.
	@# bin/ also holds python scripts: only a python shebang takes a file out.
	@for f in install.sh uninstall.sh lldpq/*.sh html/*.sh bin/* docker/*.sh telemetry/*.sh \
			lldpq/sw-base/*.sh lldpq/sw-base/cmd lldpq/sw-base/nvc lldpq/sw-base/nvt \
			lldpq/sw-base/bash.bashrc docker/dotf/bashrc docker/lldpq-vrf docker/curl-vrf; do \
		[ -f "$$f" ] || continue; \
		head -1 "$$f" | grep -q '^#!.*python' && continue; \
		bash -n "$$f" || { echo "bash -n failed: $$f"; exit 1; }; \
	done
	@echo "make test: all legs passed"

lint: test
