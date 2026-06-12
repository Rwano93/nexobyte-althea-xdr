<#
.SYNOPSIS
    Althea XDR - Demonstrateur SOC/SOAR autonome en PowerShell (PoC pedagogique).

.DESCRIPTION
    Emule la chaine SIEM + SOAR sur l'Active Directory de la maquette Althea Systems :
      - Collecte des journaux Security des controleurs de domaine (WinRM / Get-WinEvent)
      - Classification des evenements (NORMAL / ATTACK / ADMIN / SYSTEM)
      - Moteur de detection brute-force (MITRE ATT&CK T1110.001)
      - Tableau de bord web (HTML/JS, rafraichissement AJAX 15 s, 3 vues :
        Incidents / Forensic / Playbooks) servi en HTTP local
      - API SOAR locale (port 8080) declenchant les playbooks de reponse
      - Playbooks LIVE (Unlock-ADAccount, Set-ADAccountPassword) executes
        reellement sur l'AD ; playbooks STUB (Disable / Isolate / Block IP /
        Notify SOC) simules faute de brique tierce sur la maquette
      - Chat SOC Team avec recommandations automatiques du bot

    Reference DAT Etudiant 3 (Althea Systems) : paragraphes 4.9.3 et 16.4.
    En production, ces fonctions sont portees par Microsoft Sentinel +
    Microsoft Defender for Identity. Ce PoC prouve la logique
    detection -> investigation -> reponse independamment de l'outillage commercial.

.NOTES
    Auteur  : Erwan GUEGANIC - Etudiant 3, equipe Nexobyte (Sup de Vinci 2025-2026)
    Version : 13 (reconstruction depuis specifications)
    Cible   : Windows Server 2022+, PowerShell 5.1+, module ActiveDirectory (RSAT)
    Usage   : console elevee sur DC1 ->  .\AltheaXDR.ps1
              puis ouvrir http://localhost:8080

.EXAMPLE
    .\AltheaXDR.ps1 -Port 8080 -DomainControllers DC1,DC2 -Threshold 5 -WindowMinutes 5
#>

[CmdletBinding()]
param(
    [int]$Port = 8080,
    [string[]]$DomainControllers = @('DC1', 'DC2'),
    [string]$PrimaryDC = 'DC1',
    [int]$RefreshSeconds = 15,
    [int]$WindowMinutes = 5,
    [int]$Threshold = 5,
    [int]$LookbackMinutes = 120,
    [int]$MaxEventsPerDC = 400
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# Normalisation : accepte -DomainControllers DC1,DC2 (tableau PowerShell)
# comme -DomainControllers "DC1,DC2" (chaine unique, ex. appel via -File)
$DomainControllers = @($DomainControllers |
    ForEach-Object { $_ -split ',' } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne '' })

# =====================================================================
# 0. PREREQUIS
# =====================================================================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $script:AdAvailable = $true
}
catch {
    $script:AdAvailable = $false
    Write-Warning "Module ActiveDirectory indisponible : les playbooks LIVE seront refuses."
}

# =====================================================================
# 1. ETAT GLOBAL
# =====================================================================

$script:State = @{
    GeneratedAt = ''
    Kpis        = @{}
    Controllers = @()
    Events      = @()
    Incidents   = @()
    KillChain   = @()
    Sources     = @()
    LogTree     = @()
    Chat        = New-Object System.Collections.ArrayList
    Actions     = New-Object System.Collections.ArrayList
}
$script:IncidentStore = @{}   # cle = TYPE|compte -> hashtable incident
$script:LastCollect   = [datetime]::MinValue
$script:ChatSeq       = 0

function Get-UtcStamp {
    return (Get-Date).ToUniversalTime().ToString('HH:mm:ss')
}
function Get-UtcFull {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
}

function Add-ChatMessage {
    param(
        [string]$Author,
        [string]$Text,
        [string]$Kind = 'info'   # info | alert | bot | user | action
    )
    $script:ChatSeq = $script:ChatSeq + 1
    $msg = @{
        seq    = $script:ChatSeq
        time   = Get-UtcStamp
        author = $Author
        text   = $Text
        kind   = $Kind
    }
    [void]$script:State.Chat.Add($msg)
    if ($script:State.Chat.Count -gt 60) {
        $script:State.Chat.RemoveAt(0)
    }
}

function Add-ActionLog {
    param(
        [string]$Action,
        [string]$Target,
        [string]$Mode,     # LIVE | STUB
        [string]$Result
    )
    $entry = @{
        time   = Get-UtcStamp
        action = $Action
        target = $Target
        mode   = $Mode
        result = $Result
    }
    [void]$script:State.Actions.Add($entry)
    if ($script:State.Actions.Count -gt 40) {
        $script:State.Actions.RemoveAt(0)
    }
}

# =====================================================================
# 2. COLLECTE ET CLASSIFICATION DES EVENEMENTS
# =====================================================================

function Get-EvtProp {
    # Acces defensif aux proprietes d'un evenement (les index varient peu
    # mais un evenement tronque ne doit jamais faire planter le collecteur).
    param($EventRecord, [int]$Index)
    $value = ''
    if ($null -ne $EventRecord.Properties -and $EventRecord.Properties.Count -gt $Index) {
        $raw = $EventRecord.Properties[$Index].Value
        if ($null -ne $raw) { $value = [string]$raw }
    }
    return $value
}

function Get-EventLabel {
    param([int]$Id)
    $label = 'Evenement de securite'
    if ($Id -eq 4624) { $label = 'Ouverture de session reussie' }
    if ($Id -eq 4625) { $label = "Echec d'authentification" }
    if ($Id -eq 4720) { $label = 'Creation de compte utilisateur' }
    if ($Id -eq 4724) { $label = 'Reinitialisation de mot de passe' }
    if ($Id -eq 4740) { $label = 'Verrouillage de compte' }
    return $label
}

function Convert-Event {
    # Normalise un EventRecord Windows en objet plat classifie.
    param($EventRecord, [string]$Dc)

    $id      = [int]$EventRecord.Id
    $account = ''
    $source  = ''

    if ($id -eq 4624) {
        $account = Get-EvtProp $EventRecord 5
        $source  = Get-EvtProp $EventRecord 18
    }
    elseif ($id -eq 4625) {
        $account = Get-EvtProp $EventRecord 5
        $source  = Get-EvtProp $EventRecord 19
    }
    elseif ($id -eq 4740) {
        $account = Get-EvtProp $EventRecord 0
        $source  = Get-EvtProp $EventRecord 1
    }
    elseif ($id -eq 4720 -or $id -eq 4724) {
        $account = Get-EvtProp $EventRecord 0
        $source  = Get-EvtProp $EventRecord 4   # compte a l'origine de l'action
    }

    if ([string]::IsNullOrWhiteSpace($source) -or $source -eq '-') { $source = 'local' }

    # Classification ATTACK / ADMIN / NORMAL / SYSTEM
    $category = 'NORMAL'
    if ($id -eq 4625 -or $id -eq 4740) { $category = 'ATTACK' }
    if ($id -eq 4720 -or $id -eq 4724) { $category = 'ADMIN' }
    if ($id -eq 4624) {
        if ($account.EndsWith('$') -or $account -eq 'SYSTEM' -or $account -eq 'ANONYMOUS LOGON') {
            $category = 'SYSTEM'
        }
    }

    return @{
        timeRaw  = $EventRecord.TimeCreated.ToUniversalTime()
        time     = $EventRecord.TimeCreated.ToUniversalTime().ToString('HH:mm:ss')
        id       = $id
        dc       = $Dc
        account  = $account
        source   = $source
        category = $category
        label    = Get-EventLabel $id
    }
}

function Invoke-Collection {
    # Interroge les journaux Security de chaque DC et reconstruit l'etat complet.
    $events      = New-Object System.Collections.ArrayList
    $controllers = New-Object System.Collections.ArrayList
    $startTime   = (Get-Date).AddMinutes(-1 * $LookbackMinutes)

    foreach ($dc in $DomainControllers) {
        $dcInfo = @{ name = $dc; reachable = $false; count = 0; lastEvent = '-' }
        try {
            $filter = @{ LogName = 'Security'; Id = 4624, 4625, 4720, 4724, 4740; StartTime = $startTime }
            $raw = @()
            if ($dc -eq $env:COMPUTERNAME) {
                $raw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventsPerDC -ErrorAction Stop)
            }
            else {
                $raw = @(Get-WinEvent -ComputerName $dc -FilterHashtable $filter -MaxEvents $MaxEventsPerDC -ErrorAction Stop)
            }
            $dcInfo.reachable = $true
            $dcInfo.count = $raw.Count
            if ($raw.Count -gt 0) {
                $dcInfo.lastEvent = $raw[0].TimeCreated.ToUniversalTime().ToString('HH:mm:ss')
            }
            foreach ($r in $raw) {
                [void]$events.Add( (Convert-Event $r $dc) )
            }
        }
        catch [System.Exception] {
            # "Aucun evenement ne correspond" est un cas normal apres un reset demo
            if ($_.Exception.Message -like '*No events were found*' -or $_.Exception.Message -like '*Aucun*') {
                $dcInfo.reachable = $true
                $dcInfo.count = 0
            }
            else {
                $dcInfo.reachable = $false
            }
        }
        [void]$controllers.Add($dcInfo)
    }

    $sorted = @($events | Sort-Object { $_.timeRaw } -Descending)
    Update-Detection -Events $sorted -Controllers $controllers
}

# =====================================================================
# 3. MOTEUR DE DETECTION ET CORRELATION (MITRE ATT&CK)
# =====================================================================

function Update-Detection {
    param($Events, $Controllers)

    $now    = (Get-Date).ToUniversalTime()
    $window = $now.AddMinutes(-1 * $WindowMinutes)

    # --- Coeur de la logique de corrélation (cf. DAT paragraphe 16.4) ---
    # Agregation des 4625 par compte cible sur une fenetre glissante,
    # levee d'alerte au-dela du seuil (technique MITRE ATT&CK T1110.001).
    $recentFailures = @($Events | Where-Object { $_.id -eq 4625 -and $_.timeRaw -ge $window })
    $groups = @($recentFailures | Group-Object { $_.account })

    foreach ($g in $groups) {
        if ($g.Count -ge $Threshold) {
            $acct    = $g.Name
            $sources = @($g.Group | ForEach-Object { $_.source } | Sort-Object -Unique)
            $key     = 'BRUTE_FORCE|' + $acct
            $isNew   = -not $script:IncidentStore.ContainsKey($key)
            if ($isNew) {
                $script:IncidentStore[$key] = @{
                    key       = $key
                    type      = 'BRUTE-FORCE'
                    technique = 'T1110.001 - Password Guessing'
                    severity  = 'HIGH'
                    account   = $acct
                    status    = 'NEW'
                    firstSeen = Get-UtcStamp
                }
            }
            $inc = $script:IncidentStore[$key]
            $inc.count    = $g.Count
            $inc.sources  = ($sources -join ', ')
            $inc.lastSeen = Get-UtcStamp
            if ($isNew) {
                Add-ChatMessage 'XDR-Bot' ("ALERTE brute-force sur le compte " + $acct + " : " + $g.Count + " echecs 4625 en " + $WindowMinutes + " min depuis [" + $inc.sources + "]. Recommandation : playbook Reset password + verifier le verrouillage.") 'alert'
            }

            # Correlation succes-apres-echecs : 4624 sur le meme compte dans la fenetre
            $success = @($Events | Where-Object { $_.id -eq 4624 -and $_.account -eq $acct -and $_.timeRaw -ge $window })
            if ($success.Count -gt 0) {
                $key2   = 'COMPROMISE|' + $acct
                $isNew2 = -not $script:IncidentStore.ContainsKey($key2)
                if ($isNew2) {
                    $script:IncidentStore[$key2] = @{
                        key       = $key2
                        type      = 'COMPROMISSION SUSPECTEE'
                        technique = 'T1110.001 -> T1078 - Valid Accounts'
                        severity  = 'CRITICAL'
                        account   = $acct
                        status    = 'NEW'
                        firstSeen = Get-UtcStamp
                    }
                    Add-ChatMessage 'XDR-Bot' ("CRITIQUE : ouverture de session REUSSIE sur " + $acct + " apres une rafale d'echecs. Compromission probable. Recommandation immediate : Reset password (LIVE) + Isolate host (STUB) + escalade RSSI.") 'alert'
                }
                $inc2 = $script:IncidentStore[$key2]
                $inc2.count    = $success.Count
                $inc2.sources  = (@($success | ForEach-Object { $_.source } | Sort-Object -Unique) -join ', ')
                $inc2.lastSeen = Get-UtcStamp
            }
        }
    }

    # Verrouillages de compte (4740) -> incident dedie
    $lockouts = @($Events | Where-Object { $_.id -eq 4740 })
    $lockGroups = @($lockouts | Group-Object { $_.account })
    foreach ($lg in $lockGroups) {
        $acct  = $lg.Name
        $key   = 'LOCKOUT|' + $acct
        $isNew = -not $script:IncidentStore.ContainsKey($key)
        if ($isNew) {
            $script:IncidentStore[$key] = @{
                key       = $key
                type      = 'VERROUILLAGE COMPTE'
                technique = 'T1110 - Brute Force (consequence)'
                severity  = 'MEDIUM'
                account   = $acct
                status    = 'NEW'
                firstSeen = Get-UtcStamp
            }
            Add-ChatMessage 'XDR-Bot' ("Compte verrouille : " + $acct + " (event 4740). Recommandation : verifier la source puis playbook Unlock account une fois la menace ecartee.") 'alert'
        }
        $inc = $script:IncidentStore[$key]
        $inc.count    = $lg.Count
        $inc.sources  = (@($lg.Group | ForEach-Object { $_.source } | Sort-Object -Unique) -join ', ')
        $inc.lastSeen = Get-UtcStamp
    }

    # --- Kill chain (vue Forensic) ---
    $attackIps   = @($recentFailures | ForEach-Object { $_.source } | Sort-Object -Unique)
    $compromised = @($script:IncidentStore.Values | Where-Object { $_.type -eq 'COMPROMISSION SUSPECTEE' })
    $killChain = @(
        @{ stage = 'Reconnaissance';       tech = 'T1595'; count = $attackIps.Count },
        @{ stage = 'Credential Access';    tech = 'T1110'; count = @($Events | Where-Object { $_.id -eq 4625 }).Count },
        @{ stage = 'Initial Access';       tech = 'T1078'; count = $compromised.Count },
        @{ stage = 'Persistence';          tech = 'T1136'; count = @($Events | Where-Object { $_.id -eq 4720 }).Count },
        @{ stage = 'Privilege Escalation'; tech = 'T1098'; count = @($Events | Where-Object { $_.id -eq 4724 }).Count },
        @{ stage = 'Impact';               tech = 'T1531'; count = $lockouts.Count }
    )

    # --- Distribution des sources (top 6) ---
    $srcDist = @($Events | Where-Object { $_.category -eq 'ATTACK' } |
        Group-Object { $_.source } | Sort-Object Count -Descending | Select-Object -First 6 |
        ForEach-Object { @{ source = $_.Name; count = $_.Count } })

    # --- Arbre des sources de logs ---
    $logTree = @()
    foreach ($c in $Controllers) {
        $perId = @()
        foreach ($eid in @(4624, 4625, 4720, 4724, 4740)) {
            $n = @($Events | Where-Object { $_.dc -eq $c.name -and $_.id -eq $eid }).Count
            $perId += @{ id = $eid; count = $n }
        }
        $logTree += @{ dc = $c.name; log = 'Security'; ids = $perId; reachable = $c.reachable }
    }

    # --- KPIs ---
    $kpis = @{
        total     = $Events.Count
        attacks   = @($Events | Where-Object { $_.category -eq 'ATTACK' }).Count
        lockouts  = $lockouts.Count
        logons    = @($Events | Where-Object { $_.id -eq 4624 -and $_.category -eq 'NORMAL' }).Count
        incidents = @($script:IncidentStore.Values | Where-Object { $_.status -eq 'NEW' }).Count
        window    = [string]$WindowMinutes + ' min'
        threshold = $Threshold
    }

    # --- Publication de l'etat ---
    $publicEvents = @($Events | Select-Object -First 80 | ForEach-Object {
        @{ time = $_.time; id = $_.id; dc = $_.dc; account = $_.account; source = $_.source; category = $_.category; label = $_.label }
    })
    $severityRank = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3 }
    $publicIncidents = @($script:IncidentStore.Values | Sort-Object { $severityRank[$_.severity] }, { $_.lastSeen } )

    $script:State.GeneratedAt = Get-UtcFull
    $script:State.Kpis        = $kpis
    $script:State.Controllers = @($Controllers)
    $script:State.Events      = $publicEvents
    $script:State.Incidents   = $publicIncidents
    $script:State.KillChain   = $killChain
    $script:State.Sources     = $srcDist
    $script:State.LogTree     = $logTree
    $script:LastCollect       = Get-Date
}

# =====================================================================
# 4. PLAYBOOKS SOAR (LIVE + STUB)
# =====================================================================

function New-RandomPassword {
    $upper  = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower  = 'abcdefghijkmnpqrstuvwxyz'
    $digits = '23456789'
    $spec   = '!#%+'
    $all    = $upper + $lower + $digits + $spec
    $rng    = New-Object System.Random
    $chars  = New-Object System.Collections.ArrayList
    [void]$chars.Add($upper[$rng.Next(0, $upper.Length)])
    [void]$chars.Add($lower[$rng.Next(0, $lower.Length)])
    [void]$chars.Add($digits[$rng.Next(0, $digits.Length)])
    [void]$chars.Add($spec[$rng.Next(0, $spec.Length)])
    for ($i = 0; $i -lt 12; $i++) {
        [void]$chars.Add($all[$rng.Next(0, $all.Length)])
    }
    $shuffled = @($chars | Sort-Object { $rng.Next() })
    return (-join $shuffled)
}

function Set-IncidentContained {
    param([string]$Account)
    foreach ($k in @($script:IncidentStore.Keys)) {
        if ($script:IncidentStore[$k].account -eq $Account) {
            $script:IncidentStore[$k].status = 'CONTAINED'
        }
    }
}

function Invoke-Playbook {
    param([string]$Action, [string]$Account, [string]$SourceIp)

    $result = @{ ok = $false; message = '' }

    if ([string]::IsNullOrWhiteSpace($Account)) { $Account = '-' }
    if ([string]::IsNullOrWhiteSpace($SourceIp)) { $SourceIp = '-' }

    switch ($Action) {

        'unlock' {
            # Playbook LIVE - execute reellement sur l'AD de la maquette.
            if (-not $script:AdAvailable) {
                $result.message = 'Module ActiveDirectory absent : action refusee.'
                break
            }
            try {
                Unlock-ADAccount -Identity $Account -Server $PrimaryDC -Confirm:$false
                $result.ok = $true
                $result.message = 'Compte ' + $Account + ' deverrouille sur ' + $PrimaryDC + '.'
                Set-IncidentContained $Account
                Add-ActionLog 'Unlock-ADAccount' $Account 'LIVE' 'SUCCES'
                Add-ChatMessage 'SOAR' ('Playbook LIVE execute : Unlock-ADAccount sur ' + $Account + ' (DC: ' + $PrimaryDC + ').') 'action'
            }
            catch {
                $result.message = 'Echec Unlock-ADAccount : ' + $_.Exception.Message
                Add-ActionLog 'Unlock-ADAccount' $Account 'LIVE' 'ECHEC'
            }
        }

        'reset-password' {
            # Playbook LIVE - reinitialisation immediate du mot de passe.
            if (-not $script:AdAvailable) {
                $result.message = 'Module ActiveDirectory absent : action refusee.'
                break
            }
            try {
                $newPwd = New-RandomPassword
                $secure = ConvertTo-SecureString -String $newPwd -AsPlainText -Force
                Set-ADAccountPassword -Identity $Account -Server $PrimaryDC -Reset -NewPassword $secure -Confirm:$false
                $result.ok = $true
                $result.message = 'Mot de passe de ' + $Account + ' reinitialise. Nouveau mot de passe (a transmettre par canal sur) : ' + $newPwd
                Set-IncidentContained $Account
                Add-ActionLog 'Set-ADAccountPassword' $Account 'LIVE' 'SUCCES'
                Add-ChatMessage 'SOAR' ('Playbook LIVE execute : Set-ADAccountPassword sur ' + $Account + '. Genere l''event 4724 sur ' + $PrimaryDC + '.') 'action'
            }
            catch {
                $result.message = 'Echec Set-ADAccountPassword : ' + $_.Exception.Message
                Add-ActionLog 'Set-ADAccountPassword' $Account 'LIVE' 'ECHEC'
            }
        }

        'disable' {
            # STUB : en production -> Disable-ADAccount + revocation tokens Entra ID.
            $result.ok = $true
            $result.message = '[SIMULE] Compte ' + $Account + ' desactive (production : Disable-ADAccount + revocation des sessions Entra ID).'
            Set-IncidentContained $Account
            Add-ActionLog 'Disable Account' $Account 'STUB' 'SIMULE'
            Add-ChatMessage 'SOAR' ('Playbook STUB : desactivation simulee du compte ' + $Account + '.') 'action'
        }

        'isolate' {
            # STUB : en production -> isolation reseau via Defender for Endpoint.
            $result.ok = $true
            $result.message = '[SIMULE] Hote isole du reseau (production : action d''isolation Microsoft Defender for Endpoint).'
            Add-ActionLog 'Isolate Host' $Account 'STUB' 'SIMULE'
            Add-ChatMessage 'SOAR' 'Playbook STUB : isolation reseau simulee de l''hote suspect.' 'action'
        }

        'block-ip' {
            # STUB : en production -> regle de blocage poussee sur le pare-feu / NSG.
            $result.ok = $true
            $result.message = '[SIMULE] IP source ' + $SourceIp + ' bloquee (production : regle pare-feu Palo Alto / NSG Azure poussee par le SOAR).'
            Add-ActionLog 'Block Source IP' $SourceIp 'STUB' 'SIMULE'
            Add-ChatMessage 'SOAR' ('Playbook STUB : blocage simule de l''IP ' + $SourceIp + '.') 'action'
        }

        'notify' {
            # STUB : en production -> notification Teams / mail vers l'equipe SOC.
            $result.ok = $true
            $result.message = '[SIMULE] Equipe SOC notifiee (production : webhook Teams + mail astreinte).'
            Add-ActionLog 'Notify SOC' $Account 'STUB' 'SIMULE'
            Add-ChatMessage 'SOAR' 'Playbook STUB : notification SOC simulee (Teams / mail astreinte).' 'action'
        }

        default {
            $result.message = 'Playbook inconnu : ' + $Action
        }
    }

    return $result
}

function Get-BotReply {
    param([string]$Text)
    $t = $Text.ToLowerInvariant()
    $active = @($script:IncidentStore.Values | Where-Object { $_.status -eq 'NEW' })
    if ($t.Contains('unlock') -or $t.Contains('deverrouille') -or $t.Contains('déverrouille')) {
        return 'Pour deverrouiller un compte, ouvre la vue PLAYBOOKS et lance Unlock-ADAccount (LIVE) sur le compte cible.'
    }
    if ($t.Contains('reset') -or $t.Contains('mot de passe')) {
        return 'Le playbook Set-ADAccountPassword (LIVE) genere un mot de passe robuste et produit l''event 4724 - visible dans le feed Forensic.'
    }
    if ($t.Contains('status') -or $t.Contains('etat') -or $t.Contains('état')) {
        return 'Etat courant : ' + $active.Count + ' incident(s) actif(s). Voir la vue INCIDENTS pour le detail.'
    }
    if ($active.Count -gt 0) {
        return 'Note : ' + $active.Count + ' incident(s) non traite(s). Priorise les severites CRITICAL puis HIGH.'
    }
    return 'Aucun incident actif. La supervision continue (fenetre ' + $WindowMinutes + ' min, seuil ' + $Threshold + ' echecs).'
}

# =====================================================================
# 5. INTERFACE WEB (HTML + JS dans un here-string a quotes simples :
#    aucun caractere PowerShell n'y est interprete)
# =====================================================================

$script:DashboardHtml = @'
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Althea Security // XDR Platform</title>
<style>
:root {
  --bg: #0a0f1c; --panel: #0e1626; --panel2: #101b30; --border: #1e2a44;
  --txt: #cbd5e1; --muted: #64748b; --cyan: #22d3ee; --red: #f43f5e;
  --orange: #fb923c; --green: #34d399; --violet: #818cf8;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg); color: var(--txt);
  font-family: "SF Mono", "Cascadia Code", Consolas, "Courier New", monospace;
  font-size: 13px; height: 100vh; overflow: hidden;
}
#topbar {
  height: 48px; display: flex; align-items: center; gap: 16px;
  padding: 0 16px; border-bottom: 1px solid var(--border); background: var(--panel);
}
#topbar .brand { color: var(--cyan); font-weight: bold; letter-spacing: 1px; }
#topbar .brand span { color: var(--muted); font-weight: normal; }
#topbar .tabs { display: flex; gap: 4px; margin-left: 24px; }
.tabbtn {
  background: transparent; border: 1px solid var(--border); color: var(--muted);
  padding: 6px 14px; cursor: pointer; font-family: inherit; font-size: 12px;
}
.tabbtn.active { color: var(--cyan); border-color: var(--cyan); }
#clock { margin-left: auto; color: var(--muted); }
#clock b { color: var(--txt); }
#layout { display: grid; grid-template-columns: 1fr 320px; height: calc(100vh - 48px); }
#main { overflow-y: auto; padding: 16px; }
#chatpanel {
  border-left: 1px solid var(--border); background: var(--panel);
  display: flex; flex-direction: column;
}
h2.sec { color: var(--cyan); font-size: 13px; margin: 18px 0 10px 0; letter-spacing: 1px; }
h2.sec::before { content: "// "; color: var(--muted); }
.kpis { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
.kpi {
  background: var(--panel); border: 1px solid var(--border); border-top: 2px solid var(--cyan);
  padding: 10px 12px;
}
.kpi .v { font-size: 22px; color: #fff; }
.kpi .l { color: var(--muted); font-size: 11px; margin-top: 2px; }
.kpi.red { border-top-color: var(--red); }
.kpi.orange { border-top-color: var(--orange); }
.kpi.green { border-top-color: var(--green); }
.kpi.violet { border-top-color: var(--violet); }
table { width: 100%; border-collapse: collapse; background: var(--panel); }
th, td { padding: 7px 10px; border-bottom: 1px solid var(--border); text-align: left; }
th { color: var(--muted); font-weight: normal; font-size: 11px; text-transform: uppercase; }
tr:hover td { background: var(--panel2); }
.pill { padding: 2px 8px; font-size: 11px; border: 1px solid; }
.pill.CRITICAL { color: #fff; background: var(--red); border-color: var(--red); }
.pill.HIGH { color: var(--red); border-color: var(--red); }
.pill.MEDIUM { color: var(--orange); border-color: var(--orange); }
.pill.LOW { color: var(--muted); border-color: var(--muted); }
.cat { padding: 1px 7px; font-size: 11px; }
.cat.ATTACK { color: var(--red); border: 1px solid var(--red); }
.cat.ADMIN { color: var(--orange); border: 1px solid var(--orange); }
.cat.NORMAL { color: var(--green); border: 1px solid var(--green); }
.cat.SYSTEM { color: var(--muted); border: 1px solid var(--muted); }
.st.NEW { color: var(--red); }
.st.CONTAINED { color: var(--green); }
.btn {
  background: transparent; border: 1px solid var(--cyan); color: var(--cyan);
  padding: 5px 12px; cursor: pointer; font-family: inherit; font-size: 12px;
}
.btn:hover { background: var(--cyan); color: var(--bg); }
.btn.red { border-color: var(--red); color: var(--red); }
.btn.red:hover { background: var(--red); color: #fff; }
.btn.orange { border-color: var(--orange); color: var(--orange); }
.btn.orange:hover { background: var(--orange); color: var(--bg); }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.panelbox { background: var(--panel); border: 1px solid var(--border); padding: 12px; }
.bar { display: flex; align-items: center; gap: 8px; margin: 6px 0; }
.bar .lbl { width: 170px; color: var(--muted); font-size: 12px; }
.bar .track { flex: 1; background: var(--panel2); height: 14px; position: relative; }
.bar .fill { height: 14px; background: var(--cyan); }
.bar .fill.red { background: var(--red); }
.bar .n { width: 40px; text-align: right; color: #fff; }
.tree { font-size: 12px; line-height: 1.8; }
.tree .dc { color: var(--cyan); }
.tree .off { color: var(--red); }
.tree .leaf { color: var(--muted); padding-left: 22px; }
.tree .leaf b { color: var(--txt); }
.cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--border); padding: 12px; }
.card h3 { font-size: 12px; color: #fff; margin-bottom: 4px; }
.card .mode { font-size: 10px; letter-spacing: 1px; }
.card .mode.live { color: var(--green); }
.card .mode.stub { color: var(--orange); }
.card p { color: var(--muted); font-size: 11px; margin: 8px 0; min-height: 42px; }
.card input {
  width: 100%; background: var(--panel2); border: 1px solid var(--border);
  color: var(--txt); padding: 5px 8px; margin-bottom: 8px; font-family: inherit;
}
#chathead { padding: 10px 12px; border-bottom: 1px solid var(--border); color: var(--cyan); }
#chathead::before { content: "// "; color: var(--muted); }
#chatlog { flex: 1; overflow-y: auto; padding: 10px 12px; }
.msg { margin-bottom: 10px; }
.msg .meta { color: var(--muted); font-size: 10px; }
.msg .txt { font-size: 12px; margin-top: 2px; }
.msg.alert .txt { color: var(--red); }
.msg.action .txt { color: var(--green); }
.msg.bot .txt { color: var(--cyan); }
#chatform { display: flex; border-top: 1px solid var(--border); }
#chatinput {
  flex: 1; background: var(--panel2); border: 0; color: var(--txt);
  padding: 10px 12px; font-family: inherit;
}
#chatsend { border: 0; background: var(--cyan); color: var(--bg); padding: 0 16px; cursor: pointer; font-family: inherit; }
#modal {
  display: none; position: fixed; inset: 0; background: rgba(4, 8, 16, 0.78);
  align-items: center; justify-content: center; z-index: 50;
}
#modal.open { display: flex; }
#modalbox { background: var(--panel); border: 1px solid var(--cyan); width: 520px; padding: 18px; }
#modalbox h3 { color: var(--cyan); font-size: 14px; margin-bottom: 4px; }
#modalbox .sub { color: var(--muted); font-size: 11px; margin-bottom: 14px; }
#modalbox .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }
#modalresult { font-size: 12px; color: var(--green); min-height: 30px; white-space: pre-wrap; }
#modalclose { float: right; }
.view { display: none; }
.view.active { display: block; }
.footer { color: var(--muted); font-size: 11px; margin-top: 18px; }
</style>
</head>
<body>
<div id="topbar">
  <div class="brand">ALTHEA SECURITY <span>// XDR PLATFORM</span></div>
  <div class="tabs">
    <button class="tabbtn active" data-view="incidents">INCIDENTS</button>
    <button class="tabbtn" data-view="forensic">FORENSIC</button>
    <button class="tabbtn" data-view="playbooks">PLAYBOOKS</button>
  </div>
  <div id="clock">UTC <b id="clockval">--:--:--</b> &nbsp;|&nbsp; refresh <b id="refreshs">15</b>s</div>
</div>

<div id="layout">
  <div id="main">

    <div id="view-incidents" class="view active">
      <h2 class="sec">INDICATEURS TEMPS REEL</h2>
      <div class="kpis" id="kpis"></div>
      <h2 class="sec">INCIDENTS DE SECURITE</h2>
      <table>
        <thead><tr>
          <th>Severite</th><th>Type</th><th>Technique MITRE</th><th>Compte</th>
          <th>Occurrences</th><th>Sources</th><th>Premiere / derniere</th><th>Statut</th><th></th>
        </tr></thead>
        <tbody id="incrows"><tr><td colspan="9">Chargement...</td></tr></tbody>
      </table>
      <h2 class="sec">CONTROLEURS DE DOMAINE</h2>
      <table>
        <thead><tr><th>DC</th><th>Etat</th><th>Evenements collectes</th><th>Dernier evenement (UTC)</th></tr></thead>
        <tbody id="dcrows"></tbody>
      </table>
      <div class="footer" id="genat"></div>
    </div>

    <div id="view-forensic" class="view">
      <div class="grid2">
        <div class="panelbox">
          <h2 class="sec" style="margin-top:0">MITRE ATT&amp;CK KILL CHAIN</h2>
          <div id="killchain"></div>
        </div>
        <div class="panelbox">
          <h2 class="sec" style="margin-top:0">LOG SOURCE TREE</h2>
          <div class="tree" id="logtree"></div>
          <h2 class="sec">SOURCE DISTRIBUTION (ATTAQUES)</h2>
          <div id="sources"></div>
        </div>
      </div>
      <h2 class="sec">CLASSIFIED EVENT FEED</h2>
      <table>
        <thead><tr><th>Heure UTC</th><th>DC</th><th>ID</th><th>Categorie</th><th>Compte</th><th>Source</th><th>Description</th></tr></thead>
        <tbody id="feedrows"></tbody>
      </table>
    </div>

    <div id="view-playbooks" class="view">
      <h2 class="sec">PLAYBOOKS DE REPONSE</h2>
      <div class="cards">
        <div class="card">
          <h3>Unlock-ADAccount</h3><div class="mode live">LIVE - EXECUTION REELLE</div>
          <p>Deverrouille le compte sur l'AD de la maquette via le DC primaire. A utiliser une fois la menace ecartee.</p>
          <input id="pb-unlock-acct" placeholder="samAccountName">
          <button class="btn" onclick="runPlaybook('unlock', document.getElementById('pb-unlock-acct').value, '')">EXECUTER</button>
        </div>
        <div class="card">
          <h3>Set-ADAccountPassword</h3><div class="mode live">LIVE - EXECUTION REELLE</div>
          <p>Reinitialise immediatement le mot de passe du compte compromis (genere l'event 4724, visible dans le feed).</p>
          <input id="pb-reset-acct" placeholder="samAccountName">
          <button class="btn red" onclick="runPlaybook('reset-password', document.getElementById('pb-reset-acct').value, '')">EXECUTER</button>
        </div>
        <div class="card">
          <h3>Disable Account</h3><div class="mode stub">STUB - ACTION SIMULEE</div>
          <p>Production : Disable-ADAccount + revocation des sessions Entra ID. Simule sur la maquette.</p>
          <input id="pb-disable-acct" placeholder="samAccountName">
          <button class="btn orange" onclick="runPlaybook('disable', document.getElementById('pb-disable-acct').value, '')">SIMULER</button>
        </div>
        <div class="card">
          <h3>Isolate Host</h3><div class="mode stub">STUB - ACTION SIMULEE</div>
          <p>Production : isolation reseau de l'endpoint via Microsoft Defender for Endpoint.</p>
          <button class="btn orange" onclick="runPlaybook('isolate', '', '')">SIMULER</button>
        </div>
        <div class="card">
          <h3>Block Source IP</h3><div class="mode stub">STUB - ACTION SIMULEE</div>
          <p>Production : regle de blocage poussee sur le pare-feu Palo Alto / NSG Azure.</p>
          <input id="pb-block-ip" placeholder="adresse IP source">
          <button class="btn orange" onclick="runPlaybook('block-ip', '', document.getElementById('pb-block-ip').value)">SIMULER</button>
        </div>
        <div class="card">
          <h3>Notify SOC</h3><div class="mode stub">STUB - ACTION SIMULEE</div>
          <p>Production : webhook Teams + mail vers l'astreinte SOC d'Althea Systems.</p>
          <button class="btn orange" onclick="runPlaybook('notify', '', '')">SIMULER</button>
        </div>
      </div>
      <h2 class="sec">JOURNAL DES ACTIONS SOAR</h2>
      <table>
        <thead><tr><th>Heure UTC</th><th>Action</th><th>Cible</th><th>Mode</th><th>Resultat</th></tr></thead>
        <tbody id="actrows"></tbody>
      </table>
    </div>

  </div>

  <div id="chatpanel">
    <div id="chathead">SOC TEAM - ALTHEA</div>
    <div id="chatlog"></div>
    <form id="chatform" onsubmit="sendChat(); return false;">
      <input id="chatinput" placeholder="Message a l'equipe SOC..." autocomplete="off">
      <button id="chatsend" type="submit">&gt;</button>
    </form>
  </div>
</div>

<div id="modal">
  <div id="modalbox">
    <button class="btn" id="modalclose" onclick="closeModal()">FERMER</button>
    <h3 id="modaltitle">Incident</h3>
    <div class="sub" id="modalsub"></div>
    <div class="actions">
      <button class="btn" onclick="modalPlaybook('unlock')">UNLOCK ACCOUNT (LIVE)</button>
      <button class="btn red" onclick="modalPlaybook('reset-password')">RESET PASSWORD (LIVE)</button>
      <button class="btn orange" onclick="modalPlaybook('disable')">DISABLE ACCOUNT (STUB)</button>
      <button class="btn orange" onclick="modalPlaybook('isolate')">ISOLATE HOST (STUB)</button>
      <button class="btn orange" onclick="modalPlaybook('block-ip')">BLOCK SOURCE IP (STUB)</button>
      <button class="btn orange" onclick="modalPlaybook('notify')">NOTIFY SOC (STUB)</button>
    </div>
    <div id="modalresult"></div>
  </div>
</div>

<script>
var REFRESH_MS = 15000;
var currentModal = { account: "", source: "" };
var lastChatSeq = 0;

function esc(s) {
  if (s === null || s === undefined) { return ""; }
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function tickClock() {
  var d = new Date();
  function p(n) { return (n < 10 ? "0" : "") + n; }
  document.getElementById("clockval").textContent =
    p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":" + p(d.getUTCSeconds());
}
setInterval(tickClock, 1000); tickClock();

document.querySelectorAll(".tabbtn").forEach(function (b) {
  b.addEventListener("click", function () {
    document.querySelectorAll(".tabbtn").forEach(function (x) { x.classList.remove("active"); });
    document.querySelectorAll(".view").forEach(function (v) { v.classList.remove("active"); });
    b.classList.add("active");
    document.getElementById("view-" + b.dataset.view).classList.add("active");
  });
});

function renderKpis(k) {
  var html = "";
  html += "<div class='kpi'><div class='v'>" + k.total + "</div><div class='l'>EVENEMENTS COLLECTES</div></div>";
  html += "<div class='kpi red'><div class='v'>" + k.attacks + "</div><div class='l'>EVENEMENTS ATTACK</div></div>";
  html += "<div class='kpi orange'><div class='v'>" + k.lockouts + "</div><div class='l'>COMPTES VERROUILLES</div></div>";
  html += "<div class='kpi green'><div class='v'>" + k.logons + "</div><div class='l'>CONNEXIONS REUSSIES</div></div>";
  html += "<div class='kpi violet'><div class='v'>" + k.incidents + "</div><div class='l'>INCIDENTS ACTIFS (seuil " + k.threshold + "/" + esc(k.window) + ")</div></div>";
  document.getElementById("kpis").innerHTML = html;
}

function renderIncidents(list) {
  var tb = document.getElementById("incrows");
  if (!list || list.length === 0) {
    tb.innerHTML = "<tr><td colspan='9' style='color:var(--muted)'>Aucun incident detecte - annuaire sain.</td></tr>";
    return;
  }
  var html = "";
  list.forEach(function (i) {
    html += "<tr>";
    html += "<td><span class='pill " + esc(i.severity) + "'>" + esc(i.severity) + "</span></td>";
    html += "<td>" + esc(i.type) + "</td>";
    html += "<td>" + esc(i.technique) + "</td>";
    html += "<td><b>" + esc(i.account) + "</b></td>";
    html += "<td>" + esc(i.count) + "</td>";
    html += "<td>" + esc(i.sources) + "</td>";
    html += "<td>" + esc(i.firstSeen) + " / " + esc(i.lastSeen) + "</td>";
    html += "<td class='st " + esc(i.status) + "'>" + esc(i.status) + "</td>";
    html += "<td><button class='btn' onclick=\"openModal('" + esc(i.account) + "','" + esc(i.sources) + "','" + esc(i.type) + "')\">REPONDRE</button></td>";
    html += "</tr>";
  });
  tb.innerHTML = html;
}

function renderControllers(list) {
  var html = "";
  list.forEach(function (c) {
    var state = c.reachable ? "<span style='color:var(--green)'>EN LIGNE</span>" : "<span style='color:var(--red)'>INJOIGNABLE</span>";
    html += "<tr><td><b>" + esc(c.name) + "</b></td><td>" + state + "</td><td>" + esc(c.count) + "</td><td>" + esc(c.lastEvent) + "</td></tr>";
  });
  document.getElementById("dcrows").innerHTML = html;
}

function renderKillchain(stages) {
  var max = 1;
  stages.forEach(function (s) { if (s.count > max) { max = s.count; } });
  var html = "";
  stages.forEach(function (s) {
    var w = Math.round((s.count / max) * 100);
    var cls = (s.stage === "Credential Access" || s.stage === "Initial Access") ? "fill red" : "fill";
    html += "<div class='bar'><div class='lbl'>" + esc(s.stage) + " <span style='color:var(--border)'>" + esc(s.tech) + "</span></div>";
    html += "<div class='track'><div class='" + cls + "' style='width:" + w + "%'></div></div>";
    html += "<div class='n'>" + s.count + "</div></div>";
  });
  document.getElementById("killchain").innerHTML = html;
}

function renderLogTree(tree) {
  var html = "";
  tree.forEach(function (t) {
    var cls = t.reachable ? "dc" : "dc off";
    html += "<div class='" + cls + "'>&#9656; " + esc(t.dc) + " \\ Security</div>";
    t.ids.forEach(function (l) {
      html += "<div class='leaf'>event <b>" + l.id + "</b> : " + l.count + "</div>";
    });
  });
  document.getElementById("logtree").innerHTML = html;
}

function renderSources(list) {
  if (!list || list.length === 0) {
    document.getElementById("sources").innerHTML = "<div style='color:var(--muted)'>Aucune source offensive observee.</div>";
    return;
  }
  var max = 1;
  list.forEach(function (s) { if (s.count > max) { max = s.count; } });
  var html = "";
  list.forEach(function (s) {
    var w = Math.round((s.count / max) * 100);
    html += "<div class='bar'><div class='lbl'>" + esc(s.source) + "</div>";
    html += "<div class='track'><div class='fill red' style='width:" + w + "%'></div></div>";
    html += "<div class='n'>" + s.count + "</div></div>";
  });
  document.getElementById("sources").innerHTML = html;
}

function renderFeed(events) {
  var html = "";
  events.forEach(function (e) {
    html += "<tr><td>" + esc(e.time) + "</td><td>" + esc(e.dc) + "</td><td>" + e.id + "</td>";
    html += "<td><span class='cat " + esc(e.category) + "'>" + esc(e.category) + "</span></td>";
    html += "<td>" + esc(e.account) + "</td><td>" + esc(e.source) + "</td><td>" + esc(e.label) + "</td></tr>";
  });
  document.getElementById("feedrows").innerHTML = html;
}

function renderActions(list) {
  var html = "";
  for (var i = list.length - 1; i >= 0; i--) {
    var a = list[i];
    html += "<tr><td>" + esc(a.time) + "</td><td>" + esc(a.action) + "</td><td>" + esc(a.target) + "</td>";
    html += "<td>" + esc(a.mode) + "</td><td>" + esc(a.result) + "</td></tr>";
  }
  document.getElementById("actrows").innerHTML = html;
}

function renderChat(msgs) {
  var log = document.getElementById("chatlog");
  var added = false;
  msgs.forEach(function (m) {
    if (m.seq > lastChatSeq) {
      lastChatSeq = m.seq;
      added = true;
      var div = document.createElement("div");
      div.className = "msg " + m.kind;
      div.innerHTML = "<div class='meta'>[" + esc(m.time) + "] " + esc(m.author) + "</div><div class='txt'>" + esc(m.text) + "</div>";
      log.appendChild(div);
    }
  });
  if (added) { log.scrollTop = log.scrollHeight; }
}

function refresh() {
  fetch("/api/state").then(function (r) { return r.json(); }).then(function (s) {
    renderKpis(s.Kpis);
    // Le refresh AJAX preserve la modale ouverte : on ne re-rend pas son contenu.
    if (!document.getElementById("modal").classList.contains("open")) {
      renderIncidents(s.Incidents);
    }
    renderControllers(s.Controllers);
    renderKillchain(s.KillChain);
    renderLogTree(s.LogTree);
    renderSources(s.Sources);
    renderFeed(s.Events);
    renderActions(s.Actions);
    renderChat(s.Chat);
    document.getElementById("genat").textContent = "Etat genere le " + s.GeneratedAt + " UTC - Althea XDR v13 (PoC maquette, cible de production : Microsoft Sentinel + Defender for Identity)";
  }).catch(function () { /* le serveur redemarre peut-etre : on retentera */ });
}
setInterval(refresh, REFRESH_MS);
refresh();
document.getElementById("refreshs").textContent = REFRESH_MS / 1000;

function openModal(account, sources, type) {
  currentModal.account = account;
  currentModal.source = (sources || "").split(",")[0].trim();
  document.getElementById("modaltitle").textContent = type + " - " + account;
  document.getElementById("modalsub").textContent = "Sources observees : " + sources + " - choisis un playbook de reponse.";
  document.getElementById("modalresult").textContent = "";
  document.getElementById("modal").classList.add("open");
}
function closeModal() {
  document.getElementById("modal").classList.remove("open");
  refresh();
}
function modalPlaybook(action) {
  runPlaybook(action, currentModal.account, currentModal.source, true);
}

function runPlaybook(action, account, ip, inModal) {
  var body = JSON.stringify({ action: action, account: account, ip: ip });
  fetch("/api/playbook", { method: "POST", headers: { "Content-Type": "application/json" }, body: body })
    .then(function (r) { return r.json(); })
    .then(function (res) {
      if (inModal) {
        var el = document.getElementById("modalresult");
        el.style.color = res.ok ? "var(--green)" : "var(--red)";
        el.textContent = res.message;
      } else {
        alert(res.message);
        refresh();
      }
    });
}

function sendChat() {
  var input = document.getElementById("chatinput");
  var text = input.value.trim();
  if (text === "") { return; }
  input.value = "";
  fetch("/api/chat", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: text })
  }).then(function () { refresh(); });
}
</script>
</body>
</html>
'@

# =====================================================================
# 6. SERVEUR HTTP + API SOAR
# =====================================================================

function Read-RequestBody {
    param($Request)
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    $body = $reader.ReadToEnd()
    $reader.Close()
    return $body
}

function Write-Response {
    param($Response, [string]$Content, [string]$ContentType = 'application/json; charset=utf-8', [int]$Status = 200)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $Response.StatusCode = $Status
    $Response.ContentType = $ContentType
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Start-AltheaXdr {
    $listener = New-Object System.Net.HttpListener
    $prefix = 'http://+:' + $Port + '/'
    try {
        $listener.Prefixes.Add($prefix)
        $listener.Start()
    }
    catch {
        Write-Warning ("Impossible d'ecouter sur " + $prefix + " (droits admin requis). Repli sur localhost.")
        $listener = New-Object System.Net.HttpListener
        $prefix = 'http://localhost:' + $Port + '/'
        $listener.Prefixes.Add($prefix)
        $listener.Start()
    }

    Write-Host ''
    Write-Host '  =============================================================' -ForegroundColor Cyan
    Write-Host '   ALTHEA SECURITY // XDR PLATFORM  -  demonstrateur SOC/SOAR' -ForegroundColor Cyan
    Write-Host '  =============================================================' -ForegroundColor Cyan
    Write-Host ('   Dashboard : http://localhost:' + $Port + '/')
    Write-Host ('   API SOAR  : POST /api/playbook  |  Etat : GET /api/state')
    Write-Host ('   DC surveilles : ' + ($DomainControllers -join ', ') + '  (fenetre ' + $WindowMinutes + ' min, seuil ' + $Threshold + ')')
    Write-Host '   Ctrl+C pour arreter.'
    Write-Host ''

    Add-ChatMessage 'XDR-Bot' ('Plateforme Althea XDR demarree. Supervision de ' + ($DomainControllers -join ', ') + ' active (events 4624/4625/4720/4724/4740).') 'bot'

    Invoke-Collection

    while ($listener.IsListening) {
        $context  = $listener.GetContext()
        $request  = $context.Request
        $response = $context.Response
        $path     = $request.Url.AbsolutePath
        $method   = $request.HttpMethod

        try {
            if ($method -eq 'GET' -and $path -eq '/') {
                Write-Response $response $script:DashboardHtml 'text/html; charset=utf-8'
            }
            elseif ($method -eq 'GET' -and $path -eq '/api/state') {
                $age = ((Get-Date) - $script:LastCollect).TotalSeconds
                if ($age -ge ($RefreshSeconds - 2)) {
                    Invoke-Collection
                }
                $json = $script:State | ConvertTo-Json -Depth 8 -Compress
                Write-Response $response $json
            }
            elseif ($method -eq 'POST' -and $path -eq '/api/playbook') {
                $body = Read-RequestBody $request
                $payload = $null
                try { $payload = $body | ConvertFrom-Json } catch { $payload = $null }
                if ($null -eq $payload) {
                    Write-Response $response '{"ok":false,"message":"Corps JSON invalide."}' 'application/json; charset=utf-8' 400
                }
                else {
                    $res = Invoke-Playbook -Action ([string]$payload.action) -Account ([string]$payload.account) -SourceIp ([string]$payload.ip)
                    $json = $res | ConvertTo-Json -Compress
                    Write-Response $response $json
                }
            }
            elseif ($method -eq 'POST' -and $path -eq '/api/chat') {
                $body = Read-RequestBody $request
                $payload = $null
                try { $payload = $body | ConvertFrom-Json } catch { $payload = $null }
                if ($null -ne $payload -and -not [string]::IsNullOrWhiteSpace([string]$payload.text)) {
                    $text = [string]$payload.text
                    Add-ChatMessage 'Analyste' $text 'user'
                    Add-ChatMessage 'XDR-Bot' (Get-BotReply $text) 'bot'
                }
                Write-Response $response '{"ok":true}'
            }
            else {
                Write-Response $response '{"ok":false,"message":"Route inconnue."}' 'application/json; charset=utf-8' 404
            }
        }
        catch {
            try {
                Write-Response $response ('{"ok":false,"message":"Erreur interne."}') 'application/json; charset=utf-8' 500
            }
            catch { }
            Write-Warning ('Erreur de traitement HTTP : ' + $_.Exception.Message)
        }
    }
}

Start-AltheaXdr
