# Bascule des rôles FSMO — commandes de démonstration

Procédure utilisée pendant la démonstration pour prouver la résilience de l'annuaire
de la maquette Althea Systems (2 contrôleurs de domaine : DC1, DC2).

> **Conçu vs prouvé.** La cible de production documentée dans le DAT (§ 4)
> repose sur 3 contrôleurs de domaine (2 Azure + 1 on-prem) avec une répartition
> FSMO dédiée. La maquette n'en compte que 2 : la bascule ci-dessous démontre la
> **maîtrise du mécanisme** (transfert propre des rôles, vérification, retour
> arrière), pas la topologie cible complète.

## 1. État initial de la maquette

| Rôle FSMO | Détenteur initial |
|---|---|
| Schema Master | DC1 |
| Domain Naming Master | DC1 |
| Infrastructure Master | DC1 |
| PDC Emulator | DC2 |
| RID Master | DC2 |

Vérification avant bascule :

```powershell
netdom query fsmo
# ou en PowerShell :
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
```

## 2. Bascule de démonstration — transfert de tous les rôles vers DC2

Simule la perte planifiée de DC1 (maintenance) : transfert **propre** des rôles
(les deux DC sont en ligne, pas de seizure).

```powershell
Move-ADDirectoryServerOperationMasterRole -Identity "DC2" `
    -OperationMasterRole SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster, InfrastructureMaster `
    -Confirm:$false
```

Vérification après bascule :

```powershell
netdom query fsmo
```

Résultat attendu : les 5 rôles répondent `DC2.altheasystems.local`.

## 3. Retour à l'état initial (rollback)

```powershell
# Schema / Naming / Infrastructure reviennent sur DC1
Move-ADDirectoryServerOperationMasterRole -Identity "DC1" `
    -OperationMasterRole SchemaMaster, DomainNamingMaster, InfrastructureMaster `
    -Confirm:$false

# PDC / RID restent sur DC2 (etat initial de la maquette)
netdom query fsmo
```

## 4. Notes d'exploitation

- Transfert (`Move-ADDirectoryServerOperationMasterRole`) = opération **propre**,
  les deux DC coopèrent. En cas de perte définitive du détenteur, utiliser le
  paramètre `-Force` (seizure) — jamais montré en démo car destructif.
- Les modifications AD pendant la démo sont effectuées en PowerShell avec
  `-Server "DC1"` explicite : sur Windows Server 2022 Azure Edition, les
  modifications via la console `dsa.msc` ne génèrent pas l'événement 4738,
  ce qui fausserait la collecte du démonstrateur Althea XDR.
- La bascule du PDC Emulator est visible immédiatement dans le dashboard
  Althea XDR (état des contrôleurs, vue Incidents).
