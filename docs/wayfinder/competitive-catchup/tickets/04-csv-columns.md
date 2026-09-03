# 04: Richer CSV columns

**What to build:** CSV export schema extended to match the de-facto cfst
schema: adds `sent,received,loss_pct` (01) and `fail_reason` (03), keeping
existing columns in place so existing parsers keep working (append at end).

**Blocked by:** 01 (loss fields), 03 (fail_reason)

**Status:** ready-for-agent

- [ ] New columns appended, old columns unchanged in order
- [ ] Empty values render as empty cells, formula-injection guard preserved
- [ ] Header row updated; docs in export format string updated
