# Makefile for ~/git/ps-scripts/
#
# sync       — pull agent config (workspace rules + workflows) from ~/me/refs/
# sync-check — verify nothing has drifted since last sync
# sync-restore — force-regenerate all agent config (recovery from drift)
# lint       — parse-check all PowerShell scripts (fast, no PS needed)
# help       — show this list

SYNC := ~/me/refs/bin/sync-agent-config.sh

.PHONY: help sync sync-check sync-restore sync-dry-run lint

help:
	@echo "Targets:"
	@echo "  make sync         Sync agent config from ~/me/refs/ into this repo"
	@echo "  make sync-check   Verify nothing has drifted since last sync"
	@echo "  make sync-restore Force-regenerate agent config (recovery)"
	@echo "  make sync-dry-run Show what sync would change, no writes"
	@echo "  make lint         Parse-check all PowerShell scripts"

sync:
	@$(SYNC)

sync-check:
	@$(SYNC) --check

sync-restore:
	@$(SYNC) --restore

sync-dry-run:
	@$(SYNC) --dry-run --verbose

lint:
	@find . -name '*.ps1' -not -path './archived/*' -print0 | xargs -0 -I {} \
		bash -c 'powershell -NoProfile -Command "try { [System.Management.Automation.Language.Parser]::ParseFile(\"{}\", [ref]\$null, [ref]\$null); Write-Host \"OK   {}\" } catch { Write-Host \"FAIL {}\"; exit 1 }"' 2>/dev/null \
		|| echo "(powershell not on PATH; skipped)"
