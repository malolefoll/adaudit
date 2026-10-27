<#
.SYNOPSIS
    ADAudit - Audit de sécurité Active Directory en lecture seule.

.DESCRIPTION
    Analyse un domaine Active Directory et produit un rapport HTML (+ CSV/JSON)
    listant les mauvaises configurations courantes : comptes privilégiés,
    politique de mots de passe, délégations Kerberos, comptes inactifs, etc.
    Aucune modification n'est faite sur l'annuaire.

.PARAMETER Server
    Contrôleur de domaine à interroger (par défaut : DC découvert automatiquement).

.PARAMETER InactiveDays
    Nombre de jours sans connexion au-delà duquel un compte est considéré inactif (défaut : 90).

.PARAMETER OutputPath
    Dossier de sortie des rapports (défaut : .\ADAudit-Reports).

.EXAMPLE
    .\Invoke-ADAudit.ps1
.EXAMPLE
    .\Invoke-ADAudit.ps1 -Server dc01.corp.local -InactiveDays 60 -OutputPath C:\Audit

.NOTES
    Prérequis : module ActiveDirectory (RSAT), compte utilisateur du domaine.
    Licence : MIT
#>
[CmdletBinding()]
param(
    [string]$Server,
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath 'ADAudit-Reports')
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'

try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { Write-Error "Le module ActiveDirectory (RSAT) est requis : $_"; exit 1 }

$adParams = @{}
if ($Server) { $adParams.Server = $Server }

$Findings = [System.Collections.Generic.List[object]]::new()
$Now = Get-Date
$InactiveDate = $Now.AddDays(-$InactiveDays)

$SeverityWeight = @{ Critique = 20; Haute = 10; Moyenne = 5; Faible = 2; Info = 0 }

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critique', 'Haute', 'Moyenne', 'Faible', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Description,
        [string]$Recommendation,
        [object[]]$Objects = @()
    )
    $Findings.Add([pscustomobject]@{
            Id             = $Id
            Category       = $Category
            Severity       = $Severity
            Title          = $Title
            Description    = $Description
            Recommendation = $Recommendation
            Count          = @($Objects).Count
            Objects        = @($Objects | Select-Object -First 200)
        })
    Write-Host ("  [{0,-8}] {1}" -f $Severity, $Title) -ForegroundColor $(switch ($Severity) {
            'Critique' { 'Red' } 'Haute' { 'DarkYellow' } 'Moyenne' { 'Yellow' } 'Faible' { 'Cyan' } default { 'Gray' } })
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Block)
    Write-Host "[*] $Name" -ForegroundColor White
    try { & $Block }
    catch { Write-Warning "Contrôle '$Name' ignoré : $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# Collecte
# ---------------------------------------------------------------------------
Write-Host "`nADAudit v$ScriptVersion - audit en lecture seule`n" -ForegroundColor Green

$Domain = Get-ADDomain @adParams
$Forest = Get-ADForest @adParams
if (-not $Server) { $adParams.Server = $Domain.PDCEmulator }
$DomainSID = $Domain.DomainSID.Value

Write-Host "Domaine : $($Domain.DNSRoot)  |  Forêt : $($Forest.Name)  |  DC : $($adParams.Server)`n"

$userProps = 'SamAccountName', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
'PasswordNotRequired', 'AllowReversiblePasswordEncryption', 'DoesNotRequirePreAuth', 'ServicePrincipalName',
'TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo', 'AdminCount',
'SIDHistory', 'UserAccountControl', 'whenCreated', 'Description'
$Users = @(Get-ADUser -Filter * -Properties $userProps @adParams)

$compProps = 'Enabled', 'LastLogonDate', 'OperatingSystem', 'OperatingSystemVersion', 'TrustedForDelegation',
'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo', 'PrimaryGroupID', 'PasswordLastSet'
$Computers = @(Get-ADComputer -Filter * -Properties $compProps @adParams)
$DCs = @(Get-ADDomainController -Filter * @adParams)
$DCNames = $DCs.Name

function Format-User { param($u) [pscustomobject]@{ Compte = $u.SamAccountName; Actif = $u.Enabled; DerniereConnexion = $u.LastLogonDate; MdpModifie = $u.PasswordLastSet } }

# ---------------------------------------------------------------------------
# Contrôles
# ---------------------------------------------------------------------------

Invoke-Check 'Niveaux fonctionnels' {
    $legacy = 'Windows2000Domain', 'Windows2003InterimDomain', 'Windows2003Domain', 'Windows2008Domain', 'Windows2008R2Domain', 'Windows2012Domain'
    if ($Domain.DomainMode.ToString() -in $legacy) {
        Add-Finding -Id 'DOM-001' -Category 'Domaine' -Severity 'Moyenne' -Title "Niveau fonctionnel du domaine obsolète ($($Domain.DomainMode))" `
            -Description 'Un niveau fonctionnel ancien empêche l''usage de protections récentes (Protected Users, AES par défaut, etc.).' `
            -Recommendation 'Migrer les DC vers une version supportée puis élever le niveau fonctionnel.'
    }
    else {
        Add-Finding -Id 'DOM-000' -Category 'Domaine' -Severity 'Info' -Title "Niveau fonctionnel : domaine $($Domain.DomainMode), forêt $($Forest.ForestMode)"
    }
}

Invoke-Check 'Contrôleurs de domaine' {
    $old = $DCs | Where-Object { $_.OperatingSystem -match '2003|2008|2012' }
    if ($old) {
        Add-Finding -Id 'DC-001' -Category 'Contrôleurs de domaine' -Severity 'Haute' -Title 'Contrôleurs de domaine sous un OS non supporté' `
            -Description 'Ces DC ne reçoivent plus de correctifs de sécurité.' -Recommendation 'Remplacer ces DC par des versions supportées.' `
            -Objects ($old | Select-Object Name, OperatingSystem, Site)
    }
    if ($DCs.Count -lt 2) {
        Add-Finding -Id 'DC-002' -Category 'Contrôleurs de domaine' -Severity 'Moyenne' -Title 'Un seul contrôleur de domaine' `
            -Description 'Aucune redondance : la perte du DC rend le domaine indisponible.' -Recommendation 'Déployer au moins deux DC.'
    }
}

Invoke-Check 'Politique de mots de passe' {
    $p = Get-ADDefaultDomainPasswordPolicy @adParams
    $issues = @()
    if ($p.MinPasswordLength -lt 12) { $issues += "Longueur minimale = $($p.MinPasswordLength) (recommandé >= 12)" }
    if (-not $p.ComplexityEnabled) { $issues += 'Complexité désactivée' }
    if ($p.LockoutThreshold -eq 0) { $issues += 'Aucun verrouillage de compte' }
    elseif ($p.LockoutThreshold -gt 10) { $issues += "Seuil de verrouillage élevé ($($p.LockoutThreshold))" }
    if ($p.PasswordHistoryCount -lt 12) { $issues += "Historique = $($p.PasswordHistoryCount) (recommandé >= 12)" }
    if ($p.ReversibleEncryptionEnabled) { $issues += 'Chiffrement réversible activé' }
    if ($issues) {
        $sev = if ($p.MinPasswordLength -lt 8 -or $p.LockoutThreshold -eq 0 -or $p.ReversibleEncryptionEnabled) { 'Haute' } else { 'Moyenne' }
        Add-Finding -Id 'PWD-001' -Category 'Mots de passe' -Severity $sev -Title 'Politique de mots de passe par défaut faible' `
            -Description ($issues -join ' ; ') -Recommendation 'Renforcer la GPO Default Domain Policy et/ou utiliser des PSO (FGPP) pour les comptes sensibles.' `
            -Objects ($issues | ForEach-Object { [pscustomobject]@{ Probleme = $_ } })
    }
    $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * @adParams)
    Add-Finding -Id 'PWD-000' -Category 'Mots de passe' -Severity 'Info' -Title "$($fgpp.Count) politique(s) de mot de passe affinée(s) (FGPP)" `
        -Objects ($fgpp | Select-Object Name, Precedence, MinPasswordLength, AppliesTo)
}

Invoke-Check 'Groupes privilégiés' {
    $groups = @(
        @{ Name = 'Domain Admins'; Sid = "$DomainSID-512" }, @{ Name = 'Enterprise Admins'; Sid = "$DomainSID-519" },
        @{ Name = 'Schema Admins'; Sid = "$DomainSID-518" }, @{ Name = 'Administrators'; Sid = 'S-1-5-32-544' },
        @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548' }, @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549' },
        @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551' }, @{ Name = 'Print Operators'; Sid = 'S-1-5-32-550' }
    )
    $script:PrivilegedUsers = @{}
    $rows = foreach ($g in $groups) {
        try { $grp = Get-ADGroup -Identity $g.Sid @adParams } catch { continue }
        $members = @(Get-ADGroupMember -Identity $grp -Recursive @adParams | Where-Object objectClass -eq 'user')
        foreach ($m in $members) { $script:PrivilegedUsers[$m.SamAccountName] = $true }
        [pscustomobject]@{ Groupe = $grp.Name; Membres = $members.Count; Liste = ($members.SamAccountName -join ', ') }
    }
    $da = ($rows | Where-Object { $_.Groupe -eq (Get-ADGroup "$DomainSID-512" @adParams).Name }).Membres
    $sev = if ($da -gt 10) { 'Haute' } elseif ($da -gt 5) { 'Moyenne' } else { 'Info' }
    Add-Finding -Id 'PRIV-001' -Category 'Comptes privilégiés' -Severity $sev -Title "Membres des groupes privilégiés ($($script:PrivilegedUsers.Count) comptes uniques)" `
        -Description 'Le nombre d''administrateurs doit rester minimal.' -Recommendation 'Limiter les membres, utiliser des comptes d''administration dédiés et un modèle en tiers.' -Objects $rows

    $opGroups = $rows | Where-Object { $_.Groupe -match 'Operators|Opérateurs' -and $_.Membres -gt 0 }
    if ($opGroups) {
        Add-Finding -Id 'PRIV-002' -Category 'Comptes privilégiés' -Severity 'Moyenne' -Title 'Groupes « Operators » non vides' `
            -Description 'Ces groupes donnent des droits équivalents à administrateur du domaine sur les DC.' -Recommendation 'Vider ces groupes et déléguer finement.' -Objects $opGroups
    }

    $privObjs = $Users | Where-Object { $script:PrivilegedUsers.ContainsKey($_.SamAccountName) }
    $neverExp = $privObjs | Where-Object PasswordNeverExpires
    if ($neverExp) {
        Add-Finding -Id 'PRIV-003' -Category 'Comptes privilégiés' -Severity 'Haute' -Title 'Comptes privilégiés avec mot de passe qui n''expire jamais' `
            -Recommendation 'Imposer une rotation ou des mots de passe longs gérés.' -Objects ($neverExp | ForEach-Object { Format-User $_ })
    }
    $oldPwd = $privObjs | Where-Object { $_.Enabled -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $Now.AddDays(-365) }
    if ($oldPwd) {
        Add-Finding -Id 'PRIV-004' -Category 'Comptes privilégiés' -Severity 'Moyenne' -Title 'Comptes privilégiés avec un mot de passe de plus d''un an' `
            -Objects ($oldPwd | ForEach-Object { Format-User $_ })
    }
    $privSpn = $privObjs | Where-Object { $_.ServicePrincipalName }
    if ($privSpn) {
        Add-Finding -Id 'PRIV-005' -Category 'Comptes privilégiés' -Severity 'Critique' -Title 'Comptes privilégiés avec SPN (Kerberoasting)' `
            -Description 'Le hash du mot de passe peut être récupéré par tout utilisateur du domaine et cassé hors ligne.' `
            -Recommendation 'Retirer le SPN ou sortir le compte des groupes privilégiés ; utiliser des gMSA.' -Objects ($privSpn | ForEach-Object { Format-User $_ })
    }
    try {
        $pu = @(Get-ADGroupMember -Identity "$DomainSID-525" @adParams).SamAccountName
        $notProtected = $privObjs | Where-Object { $_.Enabled -and $_.SamAccountName -notin $pu }
        if ($notProtected) {
            Add-Finding -Id 'PRIV-006' -Category 'Comptes privilégiés' -Severity 'Faible' -Title 'Comptes privilégiés hors du groupe Protected Users' `
                -Recommendation 'Ajouter les comptes d''administration humains au groupe Protected Users (après tests).' -Objects ($notProtected | ForEach-Object { Format-User $_ })
        }
    } catch { }
    $orphan = $Users | Where-Object { $_.AdminCount -eq 1 -and -not $script:PrivilegedUsers.ContainsKey($_.SamAccountName) -and $_.SamAccountName -ne 'krbtgt' }
    if ($orphan) {
        Add-Finding -Id 'PRIV-007' -Category 'Comptes privilégiés' -Severity 'Faible' -Title 'Comptes avec AdminCount=1 qui ne sont plus privilégiés' `
            -Description 'Ces comptes conservent des ACL figées (AdminSDHolder) et l''héritage désactivé.' -Recommendation 'Remettre AdminCount à 0 et réactiver l''héritage.' `
            -Objects ($orphan | ForEach-Object { Format-User $_ })
    }
}

Invoke-Check 'Comptes intégrés' {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet @adParams
    $age = [int]($Now - $krbtgt.PasswordLastSet).TotalDays
    if ($age -gt 180) {
        Add-Finding -Id 'KRB-001' -Category 'Kerberos' -Severity $(if ($age -gt 730) { 'Haute' } else { 'Moyenne' }) -Title "Mot de passe krbtgt non changé depuis $age jours" `
            -Description 'Un hash krbtgt compromis permet de forger des Golden Tickets.' -Recommendation 'Réinitialiser le mot de passe krbtgt deux fois (avec délai de réplication).'
    }
    $admin = $Users | Where-Object { $_.SID.Value -eq "$DomainSID-500" }
    if ($admin -and $admin.Enabled -and $admin.PasswordLastSet -lt $Now.AddDays(-365)) {
        Add-Finding -Id 'ADM-001' -Category 'Comptes intégrés' -Severity 'Moyenne' -Title 'Administrateur intégré actif avec un mot de passe ancien' `
            -Recommendation 'Changer le mot de passe et réserver ce compte à l''urgence.' -Objects (Format-User $admin)
    }
    $guest = $Users | Where-Object { $_.SID.Value -eq "$DomainSID-501" }
    if ($guest -and $guest.Enabled) {
        Add-Finding -Id 'ADM-002' -Category 'Comptes intégrés' -Severity 'Haute' -Title 'Compte Invité activé' -Recommendation 'Désactiver le compte Invité.'
    }
}

Invoke-Check 'Attributs de comptes à risque' {
    $enabled = $Users | Where-Object Enabled
    $asrep = $enabled | Where-Object DoesNotRequirePreAuth
    if ($asrep) {
        Add-Finding -Id 'KRB-002' -Category 'Kerberos' -Severity 'Haute' -Title 'Comptes sans pré-authentification Kerberos (AS-REP Roasting)' `
            -Recommendation 'Réactiver la pré-authentification Kerberos.' -Objects ($asrep | ForEach-Object { Format-User $_ })
    }
    $spn = $enabled | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' }
    if ($spn) {
        Add-Finding -Id 'KRB-003' -Category 'Kerberos' -Severity 'Moyenne' -Title 'Comptes utilisateurs avec SPN (Kerberoastables)' `
            -Recommendation 'Utiliser des gMSA ou des mots de passe de plus de 25 caractères.' `
            -Objects ($spn | ForEach-Object { [pscustomobject]@{ Compte = $_.SamAccountName; SPN = ($_.ServicePrincipalName -join ', '); MdpModifie = $_.PasswordLastSet } })
    }
    $des = $enabled | Where-Object { $_.UserAccountControl -band 0x200000 }
    if ($des) {
        Add-Finding -Id 'KRB-004' -Category 'Kerberos' -Severity 'Moyenne' -Title 'Comptes utilisant uniquement DES' -Recommendation 'Retirer l''option « Use only DES encryption types ».' `
            -Objects ($des | ForEach-Object { Format-User $_ })
    }
    $pnr = $enabled | Where-Object PasswordNotRequired
    if ($pnr) {
        Add-Finding -Id 'PWD-002' -Category 'Mots de passe' -Severity 'Haute' -Title 'Comptes pouvant avoir un mot de passe vide (PASSWD_NOTREQD)' `
            -Recommendation 'Retirer le flag PASSWD_NOTREQD.' -Objects ($pnr | ForEach-Object { Format-User $_ })
    }
    $rev = $enabled | Where-Object AllowReversiblePasswordEncryption
    if ($rev) {
        Add-Finding -Id 'PWD-003' -Category 'Mots de passe' -Severity 'Haute' -Title 'Comptes avec chiffrement réversible du mot de passe' `
            -Recommendation 'Désactiver l''option puis changer le mot de passe.' -Objects ($rev | ForEach-Object { Format-User $_ })
    }
    $ne = $enabled | Where-Object PasswordNeverExpires
    if ($ne) {
        Add-Finding -Id 'PWD-004' -Category 'Mots de passe' -Severity 'Faible' -Title 'Comptes avec mot de passe qui n''expire jamais' `
            -Objects ($ne | ForEach-Object { Format-User $_ })
    }
    $pwdDesc = $Users | Where-Object { $_.Description -match 'pass|mdp|pwd|motdepasse|mot de passe' }
    if ($pwdDesc) {
        Add-Finding -Id 'PWD-005' -Category 'Mots de passe' -Severity 'Haute' -Title 'Mot de passe potentiellement présent dans la description' `
            -Description 'La description est lisible par tous les utilisateurs du domaine.' -Recommendation 'Nettoyer les descriptions et changer les mots de passe concernés.' `
            -Objects ($pwdDesc | Select-Object @{n = 'Compte'; e = { $_.SamAccountName } }, Description)
    }
    $sidh = $Users | Where-Object { $_.SIDHistory.Count -gt 0 }
    if ($sidh) {
        Add-Finding -Id 'ACC-001' -Category 'Comptes' -Severity 'Moyenne' -Title 'Comptes avec SIDHistory' `
            -Description 'Le SIDHistory peut être utilisé pour une élévation de privilèges.' -Recommendation 'Nettoyer le SIDHistory après migration.' -Objects ($sidh | ForEach-Object { Format-User $_ })
    }
}

Invoke-Check 'Comptes inactifs' {
    $iu = $Users | Where-Object { $_.Enabled -and ($_.LastLogonDate -lt $InactiveDate) -and $_.whenCreated -lt $InactiveDate }
    if ($iu) {
        Add-Finding -Id 'ACC-002' -Category 'Comptes' -Severity 'Moyenne' -Title "Utilisateurs actifs sans connexion depuis $InactiveDays jours" `
            -Recommendation 'Désactiver puis supprimer les comptes inutilisés.' -Objects ($iu | ForEach-Object { Format-User $_ })
    }
    $ic = $Computers | Where-Object { $_.Enabled -and $_.LastLogonDate -lt $InactiveDate }
    if ($ic) {
        Add-Finding -Id 'ACC-003' -Category 'Comptes' -Severity 'Faible' -Title "Ordinateurs actifs sans connexion depuis $InactiveDays jours" `
            -Objects ($ic | Select-Object Name, OperatingSystem, LastLogonDate)
    }
}

Invoke-Check 'Délégations Kerberos' {
    $unc = @($Computers | Where-Object { $_.TrustedForDelegation -and $_.Name -notin $DCNames }) +
    @($Users | Where-Object TrustedForDelegation)
    if ($unc) {
        Add-Finding -Id 'DEL-001' -Category 'Délégation' -Severity 'Critique' -Title 'Délégation Kerberos non contrainte (hors DC)' `
            -Description 'Tout compte s''authentifiant sur ces machines expose son TGT, y compris les administrateurs.' `
            -Recommendation 'Remplacer par de la délégation contrainte ou basée sur les ressources (RBCD).' -Objects ($unc | Select-Object Name, ObjectClass)
    }
    $t2a = @($Computers + $Users) | Where-Object TrustedToAuthForDelegation
    if ($t2a) {
        Add-Finding -Id 'DEL-002' -Category 'Délégation' -Severity 'Moyenne' -Title 'Délégation contrainte avec transition de protocole' `
            -Objects ($t2a | Select-Object Name, @{n = 'DelegueVers'; e = { $_.'msDS-AllowedToDelegateTo' -join ', ' } })
    }
}

Invoke-Check 'Systèmes d''exploitation obsolètes' {
    $obs = $Computers | Where-Object { $_.Enabled -and $_.OperatingSystem -match 'Windows (XP|Vista|7|8 |8\.1|2000|Server 2003|Server 2008|Server 2012)' }
    if ($obs) {
        Add-Finding -Id 'OS-001' -Category 'Systèmes' -Severity 'Haute' -Title 'Ordinateurs avec un OS Windows non supporté' `
            -Recommendation 'Mettre à jour ou isoler ces machines.' -Objects ($obs | Select-Object Name, OperatingSystem, LastLogonDate)
    }
}

Invoke-Check 'Configuration du domaine' {
    $root = Get-ADObject -Identity $Domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' @adParams
    $maq = $root.'ms-DS-MachineAccountQuota'
    if ($maq -gt 0) {
        Add-Finding -Id 'CFG-001' -Category 'Configuration' -Severity 'Moyenne' -Title "MachineAccountQuota = $maq" `
            -Description 'Tout utilisateur peut joindre des machines au domaine (vecteur d''attaques RBCD).' -Recommendation 'Positionner ms-DS-MachineAccountQuota à 0 et déléguer la jonction.'
    }
    $rb = Get-ADOptionalFeature -Filter "Name -like 'Recycle Bin Feature'" @adParams
    if (-not $rb.EnabledScopes) {
        Add-Finding -Id 'CFG-002' -Category 'Configuration' -Severity 'Faible' -Title 'Corbeille AD désactivée' -Recommendation 'Activer la corbeille Active Directory.'
    }
    $schema = (Get-ADRootDSE @adParams).schemaNamingContext
    $legacyLaps = Get-ADObject -SearchBase $schema -LDAPFilter '(name=ms-Mcs-AdmPwd)' @adParams
    $winLaps = Get-ADObject -SearchBase $schema -LDAPFilter '(name=ms-LAPS-Password)' @adParams
    if (-not $legacyLaps -and -not $winLaps) {
        Add-Finding -Id 'CFG-003' -Category 'Configuration' -Severity 'Haute' -Title 'LAPS non déployé' `
            -Description 'Les mots de passe administrateur locaux sont probablement identiques sur les postes.' -Recommendation 'Déployer Windows LAPS.'
    }
    $trusts = @(Get-ADTrust -Filter * @adParams)
    if ($trusts) {
        $noFilter = $trusts | Where-Object { -not $_.SIDFilteringQuarantined -and $_.Direction -ne 'Outbound' -and -not $_.IntraForest }
        Add-Finding -Id 'TRU-001' -Category 'Approbations' -Severity $(if ($noFilter) { 'Moyenne' } else { 'Info' }) -Title "$($trusts.Count) relation(s) d'approbation" `
            -Description 'Vérifier le filtrage SID sur les approbations externes entrantes.' -Objects ($trusts | Select-Object Name, Direction, TrustType, SIDFilteringQuarantined, IntraForest)
    }
}

# ---------------------------------------------------------------------------
# Score & rapports
# ---------------------------------------------------------------------------
$penalty = ($Findings | ForEach-Object { $SeverityWeight[$_.Severity] } | Measure-Object -Sum).Sum
$Score = [math]::Max(0, 100 - $penalty)
$order = @{ Critique = 0; Haute = 1; Moyenne = 2; Faible = 3; Info = 4 }
$Sorted = $Findings | Sort-Object { $order[$_.Severity] }, Id

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
$stamp = $Now.ToString('yyyyMMdd-HHmm')
$base = Join-Path $OutputPath "ADAudit_$($Domain.DNSRoot)_$stamp"

$Sorted | Select-Object Id, Category, Severity, Title, Count, Description, Recommendation |
Export-Csv "$base.csv" -NoTypeInformation -Encoding UTF8
[pscustomobject]@{
    Version = $ScriptVersion; Date = $Now; Domain = $Domain.DNSRoot; Score = $Score
    Stats = @{ Users = $Users.Count; Computers = $Computers.Count; DCs = $DCs.Count }; Findings = $Sorted
} | ConvertTo-Json -Depth 6 | Out-File "$base.json" -Encoding UTF8

function ConvertTo-SafeHtml([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }
$sevColor = @{ Critique = '#c0392b'; Haute = '#e67e22'; Moyenne = '#d4ac0d'; Faible = '#2e86c1'; Info = '#7f8c8d' }
$counts = $Order.Keys | Sort-Object { $order[$_] } | ForEach-Object {
    $k = $_; "<div class='kpi' style='border-color:$($sevColor[$k])'><b>$(@($Findings | Where-Object Severity -eq $k).Count)</b><span>$k</span></div>"
}
$cards = foreach ($f in $Sorted) {
    $table = ''
    if ($f.Objects.Count) {
        $table = ($f.Objects | ConvertTo-Html -Fragment) -join ''
        if ($f.Count -gt 200) { $table += "<p class='muted'>200 premiers objets affichés sur $($f.Count).</p>" }
        $table = "<details><summary>$($f.Count) objet(s)</summary>$table</details>"
    }
    @"
<div class='card'>
  <div class='head'><span class='sev' style='background:$($sevColor[$f.Severity])'>$($f.Severity)</span>
  <span class='id'>$($f.Id)</span><h3>$(ConvertTo-SafeHtml $f.Title)</h3><span class='cat'>$(ConvertTo-SafeHtml $f.Category)</span></div>
  $(if ($f.Description) { "<p>$(ConvertTo-SafeHtml $f.Description)</p>" })
  $(if ($f.Recommendation) { "<p class='reco'><b>Recommandation :</b> $(ConvertTo-SafeHtml $f.Recommendation)</p>" })
  $table
</div>
"@
}
$scoreColor = if ($Score -ge 80) { '#27ae60' } elseif ($Score -ge 50) { '#e67e22' } else { '#c0392b' }
$html = @"
<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>ADAudit - $($Domain.DNSRoot)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f8;color:#222;margin:0;padding:24px;max-width:1100px;margin:auto}
h1{margin:0}.muted{color:#777;font-size:13px}.top{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:16px 0}
.score{font-size:48px;font-weight:700;color:$scoreColor}.kpi{background:#fff;border-left:5px solid;padding:8px 14px;border-radius:6px;min-width:80px}
.kpi b{display:block;font-size:22px}.card{background:#fff;border-radius:8px;padding:14px 18px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.head h3{margin:0;font-size:16px;flex:1}
.sev{color:#fff;padding:2px 10px;border-radius:12px;font-size:12px}.id{font-family:monospace;color:#555}.cat{font-size:12px;color:#777}
.reco{background:#eef6ee;padding:8px;border-radius:4px}table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
th,td{border:1px solid #ddd;padding:4px 8px;text-align:left}th{background:#f0f0f0}summary{cursor:pointer;color:#2e86c1}
</style></head><body>
<h1>Rapport ADAudit</h1>
<p class='muted'>Domaine <b>$($Domain.DNSRoot)</b> · Forêt $($Forest.Name) · $($Now.ToString('dd/MM/yyyy HH:mm')) · ADAudit v$ScriptVersion</p>
<div class='top'><div><div class='score'>$Score/100</div><div class='muted'>Score de sécurité</div></div>$($counts -join '')
<div class='muted'>$($Users.Count) utilisateurs · $($Computers.Count) ordinateurs · $($DCs.Count) DC</div></div>
$($cards -join "`n")
<p class='muted'>Audit en lecture seule. Le score est indicatif et ne remplace pas une revue manuelle.</p>
</body></html>
"@
$html | Out-File "$base.html" -Encoding UTF8

Write-Host "`nScore : $Score/100  ($($Findings.Count) constats)" -ForegroundColor $(if ($Score -ge 80) { 'Green' } elseif ($Score -ge 50) { 'Yellow' } else { 'Red' })
Write-Host "Rapports : $base.html | .csv | .json`n"
