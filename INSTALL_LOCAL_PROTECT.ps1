# INSTALL_LOCAL_PROTECT.ps1 -- Local pre-push hook blocking force-push/delete on main
# Run from C:\Users\rapha\Downloads\PROJETO SOC
# This is option C from the chat: free, repo stays private, protects only YOUR machine.

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$hookDir = ".git/hooks"
$hookPath = "$hookDir/pre-push"

if (-not (Test-Path $hookDir)) {
    Write-Host "Not a git repo (no .git/hooks). Run from the project root." -ForegroundColor Red
    exit 1
}

$hookBody = @'
#!/bin/sh
# Pre-push hook: refuse force-push or delete on main / master.
# Installed by INSTALL_LOCAL_PROTECT.ps1.

protected_branches="main master"
zero="0000000000000000000000000000000000000000"

while read local_ref local_sha remote_ref remote_sha
do
    branch=$(echo "$remote_ref" | sed 's|refs/heads/||')
    case " $protected_branches " in
        *" $branch "*) ;;
        *) continue ;;
    esac

    # delete?
    if [ "$local_sha" = "$zero" ]; then
        echo "BLOCKED: refusing to delete protected branch '$branch'." >&2
        exit 1
    fi

    # force-push? (remote sha is not ancestor of local sha)
    if [ "$remote_sha" != "$zero" ]; then
        if ! git merge-base --is-ancestor "$remote_sha" "$local_sha"; then
            echo "BLOCKED: refusing non-fast-forward push to '$branch'." >&2
            echo "         Local does not contain remote ($remote_sha)." >&2
            echo "         If you really mean it: git push --no-verify --force-with-lease" >&2
            exit 1
        fi
    fi
done

exit 0
'@

# Write with LF line endings (git hooks need Unix line endings)
[System.IO.File]::WriteAllText(
    (Resolve-Path $hookDir).Path + "\pre-push",
    $hookBody.Replace("`r`n", "`n"),
    (New-Object System.Text.UTF8Encoding $false)
)

Write-Host "Hook installed: $hookPath" -ForegroundColor Green
Write-Host ""
Write-Host "What it blocks (on this machine, this clone):" -ForegroundColor Cyan
Write-Host "  - git push --force / --force-with-lease to main or master" -ForegroundColor Gray
Write-Host "  - git push :main (delete remote main)" -ForegroundColor Gray
Write-Host ""
Write-Host "Bypass for emergencies: git push --no-verify ..." -ForegroundColor Gray
Write-Host ""
Write-Host "NOTE: This is only your local machine. Other clones / web UI are not protected." -ForegroundColor Yellow
Write-Host "      For server-side protection, see options A (public repo) or B (Pro)." -ForegroundColor Yellow

# Auto-cleanup
Remove-Item -LiteralPath "INSTALL_LOCAL_PROTECT.ps1" -ErrorAction SilentlyContinue
