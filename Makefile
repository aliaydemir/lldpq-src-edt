# LLDPq test entrypoint. Test deps: pytest, pyyaml, requests, jinja2
# (install them in whatever python3 environment is on PATH; no venv is assumed).
# The node test legs use the built-in node:test runner and require Node >= 18.

.PHONY: test lint

test:
	python3 -m pytest lldpq/ -q
	node lldpq/test_ai_evidence_frontend.mjs && node lldpq/test_console_broadcast.mjs && node lldpq/test_pfc_detail_frontend.mjs
	@# bash -n sweep over shell entrypoints; bin/lldpq-* includes python scripts, so gate on the shebang.
	@for f in install.sh uninstall.sh lldpq/*.sh html/*.sh bin/lldpq bin/lldpq-* docker/docker-entrypoint.sh; do \
		head -1 "$$f" | grep -q bash || continue; \
		bash -n "$$f" || { echo "bash -n failed: $$f"; exit 1; }; \
	done
	@echo "make test: all legs passed"

lint: test
