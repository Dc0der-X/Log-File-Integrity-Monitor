# LogSentry — Makefile
#
# Everything here is optional: the tool is a shell script and runs straight
# from a checkout with ./bin/logsentry. These targets just save typing.

PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
LIBDIR      := $(PREFIX)/lib/logsentry
CONFDIR     ?= /etc/logsentry
STATEDIR    ?= /var/lib/logsentry
SHELLSCRIPTS := bin/logsentry $(wildcard lib/*.sh) demo/demo.sh tests/run_tests.sh install/install.sh

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@printf '\nLogSentry — make targets\n\n'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-12s\033[0m %s\n", $$1, $$2}'
	@printf '\n'

.PHONY: test
test: ## Run the test suite
	@./tests/run_tests.sh

.PHONY: demo
demo: ## Run the interactive walkthrough
	@./demo/demo.sh

.PHONY: demo-fast
demo-fast: ## Run the walkthrough without pauses
	@./demo/demo.sh --fast

.PHONY: lint
lint: ## Run shellcheck over every script (requires shellcheck)
	@command -v shellcheck >/dev/null 2>&1 || { \
	  echo "shellcheck not installed — see https://www.shellcheck.net"; exit 1; }
	@shellcheck --severity=warning $(SHELLSCRIPTS) && echo "shellcheck: clean"

.PHONY: syntax
syntax: ## Parse every script without running it
	@for f in $(SHELLSCRIPTS); do bash -n "$$f" || exit 1; done; echo "syntax: clean"

.PHONY: install
install: ## Install to $(PREFIX) (needs root)
	@install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(CONFDIR) $(DESTDIR)$(STATEDIR)
	@install -m 0644 lib/*.sh $(DESTDIR)$(LIBDIR)/
	@install -m 0755 bin/logsentry $(DESTDIR)$(BINDIR)/logsentry
	@[ -f $(DESTDIR)$(CONFDIR)/logsentry.conf ] \
	  || install -m 0600 config/logsentry.conf.example $(DESTDIR)$(CONFDIR)/logsentry.conf
	@chmod 0700 $(DESTDIR)$(STATEDIR)
	@printf 'Installed:\n  %s\n  %s\n  %s\n' \
	  "$(BINDIR)/logsentry" "$(LIBDIR)/" "$(CONFDIR)/logsentry.conf"
	@printf 'Next: edit %s then run: logsentry init\n' "$(CONFDIR)/logsentry.conf"

.PHONY: uninstall
uninstall: ## Remove the installed files (keeps config and baselines)
	@rm -f $(DESTDIR)$(BINDIR)/logsentry
	@rm -rf $(DESTDIR)$(LIBDIR)
	@printf 'Removed the binary and libraries.\n'
	@printf 'Kept %s and %s — delete them by hand if you mean it.\n' "$(CONFDIR)" "$(STATEDIR)"

.PHONY: check-all
check-all: syntax test ## Syntax check plus the full test suite
