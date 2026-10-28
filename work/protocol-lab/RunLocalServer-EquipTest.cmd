@echo off
rem 1.24 equipment test: the "loadout" profile (baseline + observed class-compatible scrolls,
rem clothing and accessories). The "baseline" profile stays unchanged for regression runs.
call "%~dp0RunLocalHandshake.cmd" loadout
