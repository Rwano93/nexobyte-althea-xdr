<#
.SYNOPSIS
    Remise a l'etat initial de la demonstration Althea XDR.

.DESCRIPTION
    Reinitialise la maquette entre deux passages de demonstration :
      1. Deverrouille tous les comptes AD verrouilles par le scenario de brute-force
      2. Purge le journal Security du DC local (DC1)
      3. Purge le journal Security du DC distant (DC2) via Invoke-Command
      4. Genere un evenement 4624 propre pour que le dashboard reparte d'un etat sain

    A executer dans une console elevee sur le DC primaire de la maquette.
    Le scenario d'attaque (rafale d'echecs 4625) peut ensuite etre rejoue
    pour declencher la detection T1110.001 du demonstrateur.

.NOTES
    Auteur : Erwan GUEGANIC - Etudiant 3, equipe Nexobyte (Sup de Vinci 2025-2026)
    Reference DAT : paragraphe 4.9.3 (demonstrateur Althea XDR)

.EXAMPLE
    .\Reset-Demo.ps1
    .\Reset-Demo.ps1 -RemoteDC DC2 -Force
#>

[CmdletBinding()]
param(
    [string]$PrimaryDC = 'DC1',
    [string]$RemoteDC = 'DC2',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

if (-not $Force) {
    Write-Host 'ATTENTION : ce script purge les journaux Security de la maquette.' -ForegroundColor Yellow
    $answer = Read-Host 'Confirmer la remise a l''etat initial ? (O/N)'
    if ($answer -ne 'O' -and $answer -ne 'o') {
        Write-Host 'Operation annulee.'
        return
    }
}

# --- Etape 1 : deverrouillage de tous les comptes verrouilles ---------------
Write-Host '[1/4] Deverrouillage des comptes verrouilles...' -ForegroundColor Cyan
$locked = @(Search-ADAccount -LockedOut -Server $PrimaryDC)
if ($locked.Count -eq 0) {
    Write-Host '      Aucun compte verrouille.'
}
else {
    foreach ($acct in $locked) {
        Unlock-ADAccount -Identity $acct.SamAccountName -Server $PrimaryDC -Confirm:$false
        Write-Host ('      Deverrouille : ' + $acct.SamAccountName)
    }
}

# --- Etape 2 : purge du journal Security local ------------------------------
Write-Host ('[2/4] Purge du journal Security sur ' + $env:COMPUTERNAME + '...') -ForegroundColor Cyan
wevtutil cl Security
Write-Host '      Journal local purge.'

# --- Etape 3 : purge du journal Security du DC distant ----------------------
Write-Host ('[3/4] Purge du journal Security sur ' + $RemoteDC + '...') -ForegroundColor Cyan
try {
    Invoke-Command -ComputerName $RemoteDC -ScriptBlock { wevtutil cl Security }
    Write-Host ('      Journal de ' + $RemoteDC + ' purge.')
}
catch {
    Write-Warning ($RemoteDC + ' injoignable : ' + $_.Exception.Message)
}

# --- Etape 4 : generation d'un evenement 4624 propre ------------------------
# Une simple session WinRM vers le DC genere une ouverture de session reseau
# (4624, LogonType 3) : le dashboard repart ainsi d'un etat sain et verifiable.
Write-Host '[4/4] Generation d''un evenement 4624 de reference...' -ForegroundColor Cyan
try {
    $probe = Invoke-Command -ComputerName $PrimaryDC -ScriptBlock { $env:COMPUTERNAME }
    Write-Host ('      Evenement 4624 genere sur ' + $probe + '.')
}
catch {
    Write-Warning ('Generation 4624 impossible : ' + $_.Exception.Message)
}

Write-Host ''
Write-Host 'Remise a l''etat initial terminee. La demonstration peut etre rejouee.' -ForegroundColor Green
Write-Host 'Rappel : relancer .\src\AltheaXDR.ps1 si la plateforme a ete arretee.'
