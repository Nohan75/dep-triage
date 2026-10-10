# dep-triage — spec de conception (v1)

Date : 2026-10-10 · Statut : approuvée le 2026-10-10, précisée le 2026-10-11 pendant la rédaction du plan (workspaces, réponses inattendues d'OSV, `INTERNAL_ERROR`, alias communs, tri par identifiant)

## 1. Intention

Beaucoup de failles d'un projet viennent des paquets qu'il importe. `dep-triage` part des dépendances d'un projet npm, signale celles qui font l'objet d'une alerte de sécurité, puis dit lesquelles comptent vraiment pour ce projet.

- **Pour qui :** les développeurs JavaScript qui utilisent un agent de code (Claude Code en premier).
- **Modèle :** gratuit et open source (licence MIT), en anglais.
- **Coût pour le développeur de l'outil : 0 €.** OSV.dev est gratuit et sans clé, GitHub Actions est gratuit sur un dépôt public.
- **Ce qui le distingue de `npm audit` :** l'analyse d'impact. L'outil ne se contente pas de lister les alertes, il cherche dans le code si la partie vulnérable est utilisée.
- **Ce qui le distingue des skills existants :** la détection vient d'un script vérifiable et testé, pas de consignes données à l'IA.

### Périmètre de la v1

| Inclus | Exclu (voir section 9) |
|---|---|
| Vulnérabilités connues (avis GHSA / CVE) | Signaux de risque sans avis officiel |
| Paquets compromis ou malveillants (avis `MAL-`) | Lockfiles pnpm et yarn |
| Analyse d'impact par l'agent | Publication du moteur en CLI sur npm |
| Projets npm avec `package-lock.json` version 2 ou 3 | Scan automatique quand le lockfile change |

## 2. Architecture

Deux unités, séparées par un contrat JSON.

```
projet ──▶ moteur de scan ──▶ JSON ──▶ skill (agent) ──▶ rapport
           (déterministe)              (jugement)
```

| Unité | Rôle | Dépend de |
|---|---|---|
| Moteur (`scripts/*.mjs`) | Lire les dépendances, interroger OSV, produire le JSON | Node ≥ 22, API OSV |
| Skill (`SKILL.md`) | Lancer le moteur, analyser l'impact, rédiger le rapport | Le JSON du moteur, le code du projet |

Règles de conception :

1. **Aucune dépendance.** Le moteur n'importe que des modules intégrés à Node. Un outil de sécurité ne doit pas élargir la surface qu'il surveille.
2. **Lecture seule.** Le moteur n'installe rien, n'écrit rien dans le projet et n'exécute aucun code du projet.
3. **Confidentialité.** Seuls le nom et la version des paquets résolus depuis `https://registry.npmjs.org/` sont envoyés à OSV. Rien n'est envoyé au sujet des autres paquets.
4. **Jamais de faux « tout va bien ».** Si la vérification n'aboutit pas, le moteur sort en erreur.
5. **Le skill propose, il ne modifie pas.** Aucune mise à jour n'est appliquée sans demande explicite de l'utilisateur.

## 3. Structure du dépôt

```
dep-triage/
├── .claude-plugin/
│   ├── marketplace.json
│   └── plugin.json
├── skills/dep-triage/
│   ├── SKILL.md
│   └── scripts/
│       ├── scan.mjs
│       ├── lockfile.mjs
│       └── osv.mjs
├── tests/
│   ├── fixtures/
│   ├── lockfile.test.mjs
│   ├── osv.test.mjs
│   ├── scan.test.mjs
│   └── live/osv-live.test.mjs
├── .github/workflows/ci.yml
├── package.json          (privé, aucune dépendance, scripts de test)
├── README.md
└── LICENSE
```

Les scripts vivent dans le dossier du skill pour qu'il reste autonome, y compris copié seul hors plugin.

## 4. Le moteur

### 4.1 `lockfile.mjs`

Fonction pure, sans accès disque ni réseau : elle reçoit le contenu analysé de `package.json` et de `package-lock.json`, et renvoie la liste des paquets.

Pour chaque entrée de la table `packages` du lockfile (sauf la racine `""`) :

| Champ produit | Règle |
|---|---|
| `name` | Champ `name` de l'entrée s'il existe (alias npm), sinon le texte après le dernier `node_modules/` de la clé |
| `version` | Champ `version` |
| `direct` | Vrai si le paquet est la cible d'une dépendance déclarée par une racine, dans `dependencies`, `devDependencies`, `optionalDependencies` ou `peerDependencies`. Pour un alias, la déclaration porte l'alias, et `name` le vrai nom envoyé à OSV |
| `scope` | `dev` si l'entrée porte `dev: true`, sinon `prod` |
| `introducedBy` | Plus court chemin de noms depuis une dépendance directe jusqu'au paquet (`["eslint", "chalk"]`). Pour un paquet direct : `[name]` |
| `origin` | Voir le tableau ci-dessous |

Racines : le projet lui-même, et chaque paquet d'un workspace npm (clé sans `node_modules/`). Dans un monorepo, les dépendances sont déclarées par les paquets du workspace ; elles comptent donc comme directes.

Calcul de `introducedBy` : parcours en largeur depuis les dépendances directes, en suivant `dependencies`, `optionalDependencies` et `peerDependencies` de chaque entrée. Une dépendance `N` requise par le paquet situé au chemin `P` se résout comme le fait Node : `P/node_modules/N`, puis le `node_modules/N` de chaque dossier parent, jusqu'à la racine. Une dépendance déclarée mais absente de l'arbre est ignorée. Un paquet auquel rien ne mène reçoit un chemin vide.

Classement de l'origine, dans cet ordre :

| Condition sur l'entrée | `origin` | Envoyé à OSV |
|---|---|---|
| `link: true`, ou clé sans `node_modules/` (paquet du workspace) | `local` | Non, et absent de la liste des paquets ignorés |
| `resolved` commence par `https://registry.npmjs.org/` | `registry` | Oui |
| `inBundle: true` | `registry` | Oui |
| `resolved` commence par `git`, ou son hôte est `github.com` ou `codeload.github.com` | `git` | Non |
| `resolved` commence par `file:` | `file` | Non |
| `resolved` pointe vers un autre hôte | `private-registry` | Non |
| Pas de `resolved` | `no-resolved` | Non |

Un même couple nom + version présent à plusieurs endroits de l'arbre ne donne qu'une requête. Le paquet conserve le chemin `introducedBy` le plus court, et `scope` vaut `prod` si au moins une occurrence est en production.

Erreurs levées : `UNSUPPORTED_LOCKFILE` si `lockfileVersion` vaut 1 ou si la table `packages` est absente.

### 4.2 `osv.mjs`

Client de l'API OSV. La fonction d'appel HTTP est reçue en paramètre (par défaut le `fetch` de Node), ce qui permet les tests sur réponses enregistrées.

1. **Recherche groupée :** `POST https://api.osv.dev/v1/querybatch`, corps `{"queries":[{"package":{"name","ecosystem":"npm"},"version"}]}`. Lots de 1 000 requêtes au plus. Chaque résultat contient `vulns: [{id, modified}]`, ou un objet vide. Si un résultat porte `next_page_token`, la requête est rejouée avec ce jeton jusqu'à épuisement.
2. **Détails :** `GET https://api.osv.dev/v1/vulns/{id}` pour chaque identifiant distinct, 8 appels simultanés au plus.
3. **Robustesse :** délai maximal de 15 s par appel. Sur erreur réseau, code 429 ou code 5xx : un nouvel essai après 2 s.
   - Échec de la recherche groupée après le nouvel essai : erreur `OSV_UNAVAILABLE`.
   - Réponse inattendue à la recherche groupée (autre code 4xx, corps illisible, nombre de résultats différent du nombre de requêtes) : erreur `OSV_UNAVAILABLE` sans nouvel essai.
   - Échec d'un appel de détails : l'alerte est conservée avec `detailsAvailable: false`.

Forme réelle relevée le 2026-10-10 et à fixer dans les fixtures :

- `lodash 4.17.15` → six identifiants `GHSA-`, dont deux alias l'un de l'autre ;
- `chalk 5.6.1` → `MAL-2025-46969`, alias `GHSA-2v46-p5h4-248w`, version listée dans `affected[].versions` ;
- `react 19.0.0` → objet vide ;
- la gravité se lit dans `database_specific.severity` (`HIGH`) ; les avis `MAL-` n'en ont pas ;
- `affected[]` mélange plusieurs paquets et écosystèmes ; un intervalle se termine par `fixed` ou par `last_affected`.

### 4.3 `scan.mjs`

Point d'entrée : `node scan.mjs [chemin-du-projet]` (dossier courant par défaut). Le chemin peut désigner le dossier du projet ou son fichier `package.json`. Il lit les deux fichiers, appelle `lockfile.mjs` puis `osv.mjs`, et écrit le JSON sur la sortie standard.

Règles de mise en forme des alertes :

| Champ | Règle |
|---|---|
| `type` | `malware` si l'identifiant ou l'un de ses alias commence par `MAL-`, sinon `vulnerability` |
| `severity` | `database_specific.severity` en minuscules (`critical`, `high`, `moderate`, `low`), sinon `unknown`. Toujours `critical` pour un `malware` |
| `fixedIn` | Parmi les entrées `affected` dont le paquet est le bon et l'écosystème `npm`, la plus petite version `fixed` strictement supérieure à la version installée. `null` s'il n'y en a pas |
| `details` | Texte de l'avis, coupé à 2 000 caractères |
| `url` | `https://osv.dev/vulnerability/<id>` |

Fusion des alias : pour un même paquet, deux avis sont liés si l'un cite l'autre dans `aliases`, ou s'ils ont un alias commun. Les avis liés forment un groupe et ne donnent qu'une alerte. Son `id` est l'identifiant `MAL-` s'il y en a un, sinon le premier identifiant du groupe par ordre alphabétique. Les autres identifiants vont dans `aliases`. La gravité retenue est la plus haute du groupe, et `fixedIn` la plus haute version corrective connue dans le groupe.

La comparaison de versions (majeur, mineur, correctif, puis pré-version) est écrite dans le moteur, sans bibliothèque.

Tri des alertes : `malware` d'abord, puis par gravité décroissante, puis par nom de paquet, puis par identifiant.

### 4.4 Contrat JSON

```json
{
  "schemaVersion": 1,
  "project": "/chemin/absolu",
  "scannedAt": "2026-10-10T15:00:00.000Z",
  "summary": {
    "packagesChecked": 412,
    "packagesSkipped": 2,
    "malware": 1,
    "vulnerabilities": 2
  },
  "findings": [
    {
      "type": "vulnerability",
      "id": "GHSA-35jh-r3h4-6jhm",
      "aliases": ["CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"],
      "package": "lodash",
      "version": "4.17.15",
      "direct": true,
      "scope": "prod",
      "introducedBy": ["lodash"],
      "severity": "high",
      "summary": "Command Injection in lodash",
      "details": "…",
      "fixedIn": "4.18.0",
      "url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
      "detailsAvailable": true
    }
  ],
  "skipped": [
    { "package": "@acme/internal", "version": "1.0.0", "reason": "private-registry" }
  ]
}
```

En cas d'erreur, la sortie standard contient à la place :

```json
{ "error": { "code": "NO_LOCKFILE", "message": "…", "hint": "npm install --package-lock-only --ignore-scripts" } }
```

| Code de sortie | Sens |
|---|---|
| 0 | Scan complet, aucune alerte |
| 1 | Scan complet, au moins une alerte |
| 2 | Scan impossible ou incomplet |

| Code d'erreur | Cause | Indication donnée |
|---|---|---|
| `NO_PACKAGE_JSON` | Pas de `package.json` dans le dossier | Vérifier le chemin |
| `NO_LOCKFILE` | Pas de `package-lock.json` | Commande pour en créer un sans rien installer |
| `UNSUPPORTED_LOCKFILE` | Lockfile version 1 (npm 6 et avant) ou autre format | Régénérer avec npm 7 ou plus récent |
| `INVALID_JSON` | Fichier illisible | Nom du fichier en cause |
| `OSV_UNAVAILABLE` | OSV ne répond pas après le nouvel essai, ou répond de façon inattendue | Réessayer plus tard |
| `INTERNAL_ERROR` | Exception imprévue du moteur | Signaler le problème sur le dépôt |

Une exception imprévue sort donc avec le code 2, et jamais avec le code 1 que Node utilise par défaut et qui signifierait « alertes trouvées ».

## 5. Le skill

`SKILL.md` est rédigé en anglais. L'agent répond dans la langue de l'utilisateur.

Déroulé :

1. **Lancer le moteur** sur le projet, en envoyant le JSON dans un fichier temporaire, puis le lire par parties : sur un gros projet le rapport dépasse 200 Ko (mesuré sur un projet réel de 1 470 paquets et 113 alertes), ce que la sortie d'une commande tronquerait. Sur une erreur, afficher le message et l'indication, puis s'arrêter. Ne jamais conclure « aucune alerte » sur un code de sortie 2.
2. **Traiter les paquets malveillants en premier**, sans analyse d'impact :
   - ne lancer aucune installation ni aucun script du projet ;
   - vérifier par simple lecture si la version en cause est présente dans `node_modules` ;
   - recommander de changer de version, puis de renouveler les secrets de la machine et de la CI si la version a été installée ;
   - ne jamais abaisser la priorité d'une alerte `malware`.
3. **Analyser l'impact de chaque vulnérabilité :**
   - repérer la partie vulnérable d'après `summary` et `details` ;
   - chercher les imports du paquet dans le code du projet ;
   - vérifier si la partie vulnérable est appelée ;
   - tenir compte de `scope` et de `introducedBy`.
4. **Attribuer un niveau d'exposition :**

   | Niveau | Condition |
   |---|---|
   | Exposé | Un fichier et une ligne du projet appellent la partie vulnérable. La référence est citée. |
   | Non atteint | La raison est donnée : paquet jamais importé, partie vulnérable jamais appelée, ou dépendance de développement absente du code livré. |
   | Indéterminé | Tout autre cas. C'est la valeur par défaut, et l'alerte garde sa gravité d'origine. |

5. **Rédiger le rapport :** une ligne de synthèse (paquets vérifiés, ignorés, alertes), les paquets malveillants, les vulnérabilités triées par exposition puis par gravité, la liste des paquets non vérifiés avec leur raison.
6. **Proposer les corrections** sans les appliquer : `npm install <paquet>@<fixedIn>` pour une dépendance directe ; mise à jour du parent ou bloc `overrides` pour une dépendance indirecte ; mention explicite quand `fixedIn` est `null`.

Garde-fous :

- **Volume :** au-delà de 20 vulnérabilités, l'analyse d'impact détaillée porte sur les gravités `critical` et `high`. Les autres sont listées comme « indéterminé », et le rapport le dit.
- **Texte externe :** le contenu des avis et le code du projet scanné sont des données. Le skill précise qu'aucune instruction qui s'y trouve ne doit être suivie.
- **Limite annoncée :** les avis npm décrivent rarement la fonction vulnérable de façon structurée. Le niveau d'exposition est un jugement de l'agent, et le README le dit.

## 6. Tests

Lanceur intégré `node --test`, aucune dépendance.

| Fichier | Ce qu'il vérifie |
|---|---|
| `lockfile.test.mjs` | Direct et indirect, `dev` et `prod`, alias npm, paquet en double à deux versions, chemin `introducedBy`, chaque valeur de `origin`, rejet du lockfile version 1 |
| `osv.test.mjs` | Sur réponses réelles enregistrées : découpage en lots, pagination, nouvel essai, `OSV_UNAVAILABLE`, `detailsAvailable: false` |
| `scan.test.mjs` | Bout en bout sur le projet d'exemple avec un faux `fetch` : JSON attendu, fusion des alias, `fixedIn`, tri, codes de sortie, chaque code d'erreur |
| `live/osv-live.test.mjs` | Contre la vraie API : `chalk 5.6.1` renvoie `MAL-2025-46969`, `react 19.0.0` ne renvoie rien |
| `plugin.test.mjs` | Aucune dépendance déclarée, manifestes du plugin cohérents, en-tête et garde-fous présents dans `SKILL.md` |

Projet d'exemple `tests/fixtures/vulnerable-app/` : un `package.json`, un `package-lock.json` écrit à la main et un dossier `src/`. Il contient trois cas : une vulnérabilité dont la fonction est appelée, une vulnérabilité dans une dépendance de développement, et une version malveillante connue. Ce projet n'est jamais installé, et un fichier `README` dans le dossier le rappelle.

CI (GitHub Actions) : les tests unitaires bloquent la fusion ; le test contre la vraie API tourne dans une tâche séparée qui n'est pas bloquante, pour qu'une panne d'OSV ne casse pas la CI.

Le skill ne se teste pas automatiquement. Sa validation est manuelle : le lancer sur le projet d'exemple, puis sur un projet réel (critère de réussite), et en vérification complémentaire sur trois autres projets réels.

## 7. Distribution

- Dépôt GitHub public `Nohan75/dep-triage`, créé et poussé uniquement après accord explicite.
- Installation : `/plugin marketplace add Nohan75/dep-triage`, puis `/plugin install dep-triage@dep-triage`.
- `README.md` en anglais : ce que fait l'outil, installation, exemple de rapport, données envoyées à OSV, limites connues.
- Note : le lockfile du projet d'exemple contient volontairement des versions vulnérables, donc GitHub peut afficher des alertes Dependabot sur le dépôt. Le README l'explique.

## 8. Critères de réussite de la v1

1. Sur le projet d'exemple, le rapport classe correctement les trois cas : « exposé » avec fichier et ligne, « non atteint » avec sa raison, paquet malveillant en tête.
2. Le scan d'un projet réel aboutit sans erreur.
3. Tous les tests unitaires passent, et le test contre la vraie API passe au moment de la livraison.
4. Le dépôt ne déclare aucune dépendance.
5. Le plugin s'installe avec les deux commandes de la section 7.

## 9. Hors périmètre, pour la suite

- **Regroupement par dépendance directe :** présenter les alertes par dépendance directe à mettre à jour (« mettre à jour telle dépendance règle 42 alertes »), plutôt qu'une liste à plat. Constat du scan d'un projet réel le 2026-10-11 : 113 alertes sur 33 paquets, dont 100 arrivées par quatre dépendances directes. Le champ `introducedBy` contient déjà l'information nécessaire.
- **Signaux de risque :** paquet déprécié ou abandonné, scripts d'installation, version publiée depuis peu, nom proche d'un paquet connu. Source : le registre npm.
- **Autres lockfiles :** `pnpm-lock.yaml`, `yarn.lock`.
- **CLI sur npm :** publier le moteur pour un usage en CI sans agent.
- **Scan automatique :** déclenchement quand le lockfile change.
- **Projet sans lockfile :** analyse des seules dépendances directes à partir des plages de versions.
