# Althea XDR — Démonstrateur SOC / SOAR (PowerShell)

Démonstrateur de supervision de l'annuaire Active Directory développé dans le cadre du projet d'études Bachelor 3 CPI Systèmes, Réseaux & Cloud (Sup de Vinci, 2025-2026) — équipe **Nexobyte**, client fictif **Althea Systems**.

> ⚠️ **Preuve de concept pédagogique.** Ce démonstrateur émule en PowerShell la chaîne SIEM + SOAR (collecte, corrélation, tableau de bord, playbooks de réponse) faute de licence sur l'environnement de maquette. La cible de production documentée dans le DAT reste **Microsoft Sentinel + Microsoft Defender for Identity**. Ce code n'est pas destiné à un usage en production.

## Contexte

Le cahier des charges Althea Systems exige une surveillance renforcée de l'Active Directory : l'annuaire est la cible privilégiée des attaques, la majorité des compromissions passant par l'exploitation de comptes utilisateurs ou administrateurs. Ce PoC prouve de bout en bout la chaîne **détection → investigation → réponse** sur l'annuaire de la maquette (2 contrôleurs de domaine Hyper-V : DC1, DC2).

## Fonctionnalités

- **Collecte** : interrogation en continu des journaux de sécurité Windows des deux DC via PowerShell / WinRM
- **Événements surveillés** : 4624 (ouverture de session), 4625 (échec d'authentification), 4720 (création de compte), 4724 (réinitialisation de mot de passe), 4740 (verrouillage de compte)
- **Classification** : chaque événement est catégorisé NORMAL / ATTACK / ADMIN / SYSTEM
- **Moteur de détection** : agrégation des 4625 par compte sur fenêtre glissante, alerte au-delà du seuil (≥ 5 échecs / 5 min) — technique MITRE ATT&CK **T1110.001** (Password Guessing)
- **Tableau de bord web** (HTML / JavaScript, rafraîchissement AJAX 15 s) : volumétrie des connexions, comptes verrouillés, inventaire de l'annuaire, état des contrôleurs, vues Incidents / Forensic / Kill Chain MITRE / Playbooks
- **API SOAR locale** (HTTP, port 8080) : déclenchement des playbooks de réponse depuis le dashboard
- **Playbooks LIVE** (exécutés réellement sur l'AD de maquette) : `Unlock-ADAccount`, `Set-ADAccountPassword`
- **Playbooks STUB** (actions simulées, faute de brique tierce) : désactivation de compte, isolation réseau, blocage IP source, notification SOC
- **Remise à l'état initial** : procédure rejouable (déverrouillage des comptes, purge des journaux Security DC1/DC2, génération d'un événement 4624 sain) pour réinitialiser la démonstration

## Prérequis

- Windows Server 2022+ avec rôle AD DS (maquette : 2 DC)
- PowerShell 5.1+, module `ActiveDirectory` (RSAT)
- WinRM activé entre la machine d'exécution et les DC
- Compte disposant des droits de lecture des journaux Security et de gestion des comptes AD
- Port 8080 disponible en local pour l'API SOAR

## Installation et lancement

```powershell
# 1. Cloner le dépôt sur le serveur de supervision (ou DC1 en maquette)
git clone https://github.com/Rwano93/nexobyte-althea-xdr.git
cd nexobyte-althea-xdr

# 2. Lancer le démonstrateur (console élevée)
.\src\AltheaXDR.ps1

# 3. Ouvrir le tableau de bord
# http://localhost:8080
```

## Remise à l'état initial de la démonstration

```powershell
.\scripts\Reset-Demo.ps1
```

Déverrouille les comptes de test, purge les journaux Security de DC1/DC2 et génère un événement 4624 propre, afin de pouvoir rejouer le scénario d'attaque (brute-force simulé) depuis un état vierge.

## Arborescence du dépôt

```
nexobyte-althea-xdr/
├── README.md
├── src/
│   └── AltheaXDR.ps1          # Démonstrateur complet (collecteur + détection + dashboard + API SOAR)
├── scripts/
│   └── Reset-Demo.ps1         # Remise à l'état initial de la démonstration
└── docs/
    ├── architecture.png       # Schéma d'architecture du démonstrateur (Figure 12 du DAT)
    └── fsmo-bascule.md        # Commandes de bascule FSMO utilisées en démo (Move-ADDirectoryServerOperationMasterRole)
```

## Lien avec le DAT

Ce dépôt accompagne le **Document d'Architecture Technique — périmètre Étudiant 3 (AD / Messagerie / Fichiers / VDI)** :
- § 4.9.3 — Supervision opérationnelle de l'annuaire (architecture du démonstrateur)
- § 16.4 — Extrait commenté du cœur de la logique de détection

## Sécurité

Aucun identifiant, mot de passe ou information d'infrastructure réelle n'est présent dans ce dépôt. L'ensemble des noms (domaine, comptes, machines) appartient à l'environnement de maquette du client fictif Althea Systems.

## Auteur

Erwan GUEGANIC — Étudiant 3, équipe Nexobyte
Bachelor 3 CPI Systèmes, Réseaux & Cloud — Sup de Vinci, 2025-2026
