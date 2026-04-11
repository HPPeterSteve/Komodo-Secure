/*
Autor: Peter Steve - 11/04/2026
VAULT SECURITY SYSTEM - FULL DOCUMENTATION (MODULAR)

create a function DisabledWrite() that creates a sandboxed process with no write permissions to the filesystem. This process should be able to read files but not modify or create any files. The function should use Windows API to create a restricted token and set up the necessary security attributes to achieve this level of isolation. Additionally, ensure that the sandboxed process is killed when the main application exits.

*/