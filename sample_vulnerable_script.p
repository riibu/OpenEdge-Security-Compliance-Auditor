/* ========================================================== */
/* SAMPLE VULNERABLE PROGRESS OPENEDGE ABL SCRIPT             */
/* Used for testing the Autonomous Patching Agent             */
/* ========================================================== */

DEFINE VARIABLE cUserInput AS CHARACTER NO-UNDO.
cUserInput = "malicious_payload.sh".

/* Vulnerability 1: Insecure OS-COMMAND execution without validation */
OS-COMMAND VALUE("sh " + cUserInput).

/* Vulnerability 2: Dynamic query execution without auth check */
DEFINE VARIABLE hQuery AS HANDLE NO-UNDO.
CREATE QUERY hQuery.
hQuery:SET-BUFFERS(BUFFER Customer:HANDLE).
hQuery:QUERY-OPEN("FOR EACH Customer WHERE Customer.Balance > 1000").