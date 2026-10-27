# ADAudit

Outil PowerShell d'**audit de sécurité Active Directory**, en lecture seule. Il analyse un domaine et génère un rapport HTML clair (avec score), plus des exports CSV et JSON.

> Aucune modification n'est effectuée sur l'annuaire : l'outil ne fait que des requêtes LDAP via le module ActiveDirectory.

## Contrôles effectués

| Catégorie | Contrôles |
|---|---|
| Domaine / DC | Niveau fonctionnel, OS des contrôleurs de domaine, redondance |
| Mots de passe | Politique par défaut, FGPP, `PASSWD_NOTREQD`, chiffrement réversible, mots de passe sans expiration, mots de passe dans la description |
| Comptes privilégiés | Membres des groupes sensibles (Domain/Enterprise/Schema Admins, Operators…), SPN sur comptes admin, ancienneté des mots de passe, Protected Users, `AdminCount` orphelins |
| Kerberos | Âge du mot de passe `krbtgt`, AS-REP Roasting, Kerberoasting, DES uniquement |
| Délégation | Délégation non contrainte (hors DC), délégation contrainte avec transition de protocole |
| Comptes | Utilisateurs et ordinateurs inactifs, `SIDHistory`, compte Invité, Administrateur intégré |
| Systèmes | OS Windows non supportés |
| Configuration | `MachineAccountQuota`, corbeille AD, présence de LAPS, approbations et filtrage SID |

Chaque constat a une sévérité (Critique, Haute, Moyenne, Faible, Info), une description, une recommandation et la liste des objets concernés.

## Prérequis

- Windows avec le module **ActiveDirectory** (RSAT) ou un contrôleur de domaine
- PowerShell 5.1 ou 7+
- Un compte utilisateur du domaine (aucun droit d'administration requis pour la plupart des contrôles)

## Utilisation

```powershell
# Audit du domaine courant
.\Invoke-ADAudit.ps1

# DC spécifique, seuil d'inactivité à 60 jours, dossier de sortie personnalisé
.\Invoke-ADAudit.ps1 -Server dc01.corp.local -InactiveDays 60 -OutputPath C:\Audit
```

Si l'exécution de scripts est bloquée :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Les rapports sont générés dans `.\ADAudit-Reports\` :

- `ADAudit_<domaine>_<date>.html` : rapport lisible avec score
- `ADAudit_<domaine>_<date>.csv` : liste des constats
- `ADAudit_<domaine>_<date>.json` : export complet (objets inclus)

## Score

Le score part de 100 et retire des points par constat : Critique −20, Haute −10, Moyenne −5, Faible −2. Il est indicatif et ne remplace pas une revue manuelle.

## Avertissement

À utiliser uniquement sur des environnements que vous administrez ou pour lesquels vous avez une autorisation écrite. Les rapports contiennent des informations sensibles sur votre domaine : ne les publiez pas.

## Contribuer

Les contributions sont bienvenues : nouveaux contrôles, corrections, traductions. Ouvrez une issue ou une Pull Request.

## Licence

[MIT](LICENSE)
