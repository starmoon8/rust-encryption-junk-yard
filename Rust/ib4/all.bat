@echo off
setlocal enabledelayedexpansion

set DUMP_FILE=file_dump.txt

> %DUMP_FILE% echo Dumping project files...

echo. >> %DUMP_FILE%
echo --- Cargo.toml --- >> %DUMP_FILE%
type Cargo.toml >> %DUMP_FILE%

echo. >> %DUMP_FILE%
echo --- .env --- >> %DUMP_FILE%
if exist .env (
    type .env >> %DUMP_FILE%
) else (
    echo .env not found >> %DUMP_FILE%
)

echo. >> %DUMP_FILE%
echo --- static/default.css --- >> %DUMP_FILE%
if exist static\default.css (
    type static\default.css >> %DUMP_FILE%
) else (
    echo static/default.css not found >> %DUMP_FILE%
)

echo. >> %DUMP_FILE%
echo --- src/main.rs --- >> %DUMP_FILE%
if exist src\main.rs (
    type src\main.rs >> %DUMP_FILE%
) else (
    echo src/main.rs not found >> %DUMP_FILE%
)

echo. >> %DUMP_FILE%
echo --- migrations/20260102123456_create_posts_table.sql --- >> %DUMP_FILE%
if exist migrations\20260102123456_create_posts_table.sql (
    type migrations\20260102123456_create_posts_table.sql >> %DUMP_FILE%
) else (
    echo migrations/20260102123456_create_posts_table.sql not found >> %DUMP_FILE%
)

echo Dump complete. Output in %DUMP_FILE%.
pause