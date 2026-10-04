# garde-secrets

Plugin pour Claude Code. Il bloque, **avant exécution**, ce qui ferait sortir un secret de ta machine :
Claude ne peut plus lire ni afficher un fichier secret, ni imprimer un jeton, ni commiter une clé.
Et **après exécution**, il masque les secrets reconnaissables dans la sortie des commandes avant que Claude la lise
(voir [Masquage des sorties](#masquage-des-sorties)).

Il ne change rien à ta façon de travailler : tant que rien de sensible n'est en jeu, tu ne le vois pas.

## Installation

Rien d'autre à installer : le plugin est exécuté par Claude Code lui-même, sous Windows, macOS et Linux.
(Si Python 3 est présent, il sert de second filet pour les versions de Claude Code trop anciennes pour le module intégré.)

**Depuis le dépôt** (mises à jour faciles) :

```
claude plugin marketplace add barthdvs/garde-secrets
claude plugin install garde-secrets@garde-secrets
```

**Ou à partir du dossier** (reçu en .zip, par exemple) : copie le dossier `garde-secrets` dans
`~/.claude/skills/` (sous Windows : `%USERPROFILE%\.claude\skills\`). Il est chargé à la session suivante.

Dans les deux cas, ouvre ensuite une **nouvelle session** Claude Code.

## Vérifier que ça marche

Dans une session, demande à Claude : « crée un fichier `.env` contenant `A=1`, puis lis-le ».
La lecture doit être refusée avec un message qui commence par `garde-secrets :`.
Si le fichier est lu, le plugin n'est pas actif : vérifie `claude plugin list`, mets Claude Code à jour, ou installe Python 3.

Pour le masquage : demande « lance `echo 'https://example.com/api?apikey=abcabcabcabc'` et recopie la sortie ».
La sortie recopiée doit contenir `apikey=<masqué par garde-secrets>`.

Pour le banc d'essai complet : `claude plugin test <dossier du plugin>` (module intégré) et
`python3 tests/cas.py` (secours Python, doit finir par `0 échec`). Les deux lisent les mêmes cas.

## Ce qui est bloqué

| Situation | Exemples |
|---|---|
| Lire ou afficher un fichier secret | `.env`, `*.key`, `*.pem`, clés SSH (`id_rsa`, `id_ed25519`…), `*.p12`, `*.kdbx`, `~/.aws/credentials`, `~/.netrc`, `~/.kube/config`, dossiers `secrets/` |
| Fichiers système et réseau | `/etc/shadow`, `/etc/gshadow` (et leurs copies `shadow-`), `wpa_supplicant*.conf`, `chap-secrets` / `pap-secrets` (PPP), `keepalived.conf` ; `getent shadow` |
| Stockage et sauvegardes | `rclone.conf`, `~/.s3cfg`, fichier de mot de passe d'un dépôt restic (`/etc/restic/password`, `.restic-password`, `restic.pass`…) |
| Bitwarden / Vaultwarden | lecture de la base (`db.sqlite3`) et de `config.json` d'un dossier `vaultwarden`, `bitwarden`, `vw-data` ou `bwdata` ; `sqlite3 … .dump` ou `SELECT` sur cette base ; CLI `bw` : `bw export` (sauf `encrypted_json`), `bw get password` / `item` / `totp` / `notes`, `bw list items`, `bw unlock`, `bw login`, `echo $BW_SESSION` |
| Terraform / OpenTofu | lecture de `*.tfstate`, `*.tfvars`, plans enregistrés ; `terraform show`, `state pull`, `state show`, `console`, `output -json`, `output -raw`, `output <nom>`, `TF_LOG=DEBUG` |
| Afficher des variables d'environnement | `env`, `printenv`, `export -p`, `echo $MON_TOKEN` ; sous PowerShell : `Get-ChildItem Env:`, `echo $env:MON_TOKEN` |
| Commandes qui impriment un secret | `gh auth token`, `gcloud auth print-access-token`, `aws configure get`, `vault kv get`, `kubectl get secret -o yaml`, `docker inspect`, `docker compose config`, `op read` |
| Faire entrer un secret dans git | `git add` ou `git commit` d'un fichier secret, ou d'un contenu reconnu : clé privée, clé AWS, jeton GitHub/GitLab/Slack, clé d'API, JWT, mot de passe écrit en dur, identifiants dans une URL |
| Secret dans la sortie d'une commande | pas bloqué mais **masqué** : voir ci-dessous |

Le message de refus nomme le fichier ou la variable, jamais la valeur.

## Masquage des sorties

Une commande anodine peut renvoyer un secret : un message d'erreur qui recopie l'URL appelée
(`…/api?t=movie&apikey=…`), un `curl -v` qui affiche l'en-tête `Authorization`, un fichier de
configuration listé par un outil. Le contrôle avant exécution ne peut pas le prévoir.

Le plugin relit donc la sortie de **Bash** et **PowerShell** avant que Claude la lise, et remplace la
**valeur** de chaque secret reconnu (jamais son nom) par `<masqué par garde-secrets>` ; le reste de la
sortie est inchangé. Claude reçoit une courte note : « garde-secrets : 1 valeur secrète masquée dans
cette sortie (paramètre d'URL « apikey »). Ne cherche pas à les retrouver. »

| Ce qui est masqué | Exemples |
|---|---|
| Paramètres d'URL nommés comme un secret | `?apikey=…`, `&api_key=…`, `&token=…`, `&access_token=…`, `&X-App-Token=…`, `&password=…`, `&sig=…`, `&signature=…`, `&client_secret=…` |
| Mot de passe dans une URL | `postgres://appli:…@db.example.com/base` |
| En-têtes d'authentification | `Authorization: Bearer …` (et `Basic`, `Token`…), `X-Api-Key: …`, `X-Auth-Token: …`, `Private-Token: …`, y compris en JSON ou dans un `curl -H` affiché |
| Champs nommés comme un secret | `"password": "…"`, `api_key: …`, `client_secret=…`, `DB_PASSWORD=…`, `--password=…`, `BW_SESSION="…"`, quand la valeur ressemble à un vrai secret (8 caractères ou plus, lettres et chiffres) |
| Jetons reconnaissables | bloc de clé privée entier, clés AWS, jetons GitHub, GitLab, Slack, Anthropic, OpenAI, Google, Stripe, Vault, npm, Scaleway, JWT |

Ne sont pas masqués : les noms (`token_url=…`, `password_file=…`, `token_type`), les valeurs vides ou
factices (`********`, `<jeton>`, `${API_KEY}`, `$TOKEN`), une phrase qui contient `key=value` hors d'une URL.

Limites, à connaître :

- Seule la sortie de Bash et PowerShell est relue. Ce que renvoient les autres outils (lecture web, outils MCP…) ne l'est pas.
- Un secret sans forme reconnaissable (une suite de caractères sans nom de champ autour) passe.
- C'est Claude qui ne voit pas la valeur. Ce qui s'affiche dans ton terminal pendant que la commande tourne
  n'est pas concerné. Pour une commande en échec (code de sortie non nul), l'affichage du résultat et le
  journal de la session sur ton disque gardent la valeur ; pour une commande réussie, ils montrent la sortie masquée.
- Une sortie trop longue est rangée dans un fichier par Claude Code, qui n'en lit qu'un extrait : le fichier, lui, n'est pas masqué.
- Le masquage complet n'existe qu'avec le module intégré. Le secours Python masque la sortie des commandes
  réussies seulement, et seulement sur une version de Claude Code qui accepte le remplacement de sortie
  (`updatedToolOutput`) pour ses outils intégrés ; sur une version plus ancienne, il ne masque rien.

## Ce qui reste permis

- Copier, déplacer, supprimer un fichier secret ; lire sa taille et ses droits (`ls`, `stat`).
- Comparer des empreintes : `sha256sum < fichier`.
- Utiliser un secret sans l'afficher : `curl -H "Authorization: Bearer $API_TOKEN" …`, `ssh -i ~/.ssh/id_ed25519 …`, `docker run --env-file .env …`.
- Les fichiers modèles : `.env.example`, `*.tfvars.example`, `*.sample`, `*.template`.
- Utiliser ces fichiers sans les afficher : `restic --password-file /etc/restic/password snapshots`, `rclone --config … ls`,
  `sqlite3 …/db.sqlite3 .tables` ou `".backup '…'"`, `bw status`, `bw sync`, `bw lock`, `bw list folders`,
  `export BW_SESSION=$(bw unlock --raw …)` (la clé ne s'affiche pas), `bw export --format encrypted_json`.
- Terraform au quotidien : `init`, `validate`, `fmt`, `plan`, `apply`, `state list`, `output` sans argument.

## Terraform : ce qu'il faut savoir

`terraform plan` et `apply` restent autorisés. Terraform y masque les valeurs marquées sensibles,
mais **pas les autres** : déclare tes variables et sorties secrètes avec `sensitive = true`,
sinon leur valeur peut apparaître dans la sortie du plan.

## Ajouter tes propres fichiers secrets

Crée `~/.config/garde-secrets/motifs.txt`, une expression régulière par ligne (les lignes `#` sont ignorées) :

```
# exports clients
clients.*\.csv$
(^|/)licence\.dat$
```

Ces motifs s'ajoutent à la liste de base ; ils ne peuvent rien en retirer. Reste sur des expressions
simples (pas de `(?i)` en tête) : elles sont lues par deux moteurs.

## En cas de blocage à tort

Le plugin ne surveille que ce que fait Claude. Si un refus est une erreur (un faux jeton dans un jeu de
tests, par exemple), fais l'opération toi-même dans ton terminal : ton `git commit` à toi n'est pas contrôlé.

## Limites

- C'est un garde-fou contre les fuites par inadvertance, pas un bac à sable : un script écrit exprès pour
  lire un secret (`python -c "open('.env')…"`) n'est pas détecté.
- Une base Bitwarden / Vaultwarden rangée ailleurs que dans un dossier qui porte ce nom n'est pas reconnue :
  ajoute son chemin à tes motifs (ci-dessus) ; le contrôle de `sqlite3` s'applique alors à elle aussi. Sur une base
  secrète, tout `SELECT` est refusé, même un simple `count(*)`.
- Le contrôle des commits et le masquage des sorties reconnaissent des formes connues de secrets. Un secret sans forme reconnaissable
  (une suite de lettres quelconque, sans mot-clé autour) passe.
- Le module intégré s'appuie sur une interface de Claude Code encore en accès anticipé : elle peut changer
  d'une version à l'autre. Sur une version qui ne le charge pas, seul le secours Python protège ; sans
  Python non plus, le plugin ne bloque rien. D'où la vérification ci-dessus, à refaire après une grosse mise à jour.
- Testé sous Linux. Les règles Windows (PowerShell) sont couvertes par le banc d'essai mais n'ont pas été
  essayées sur un vrai poste Windows : fais la vérification après installation.

## Mettre à jour, désactiver

```
claude plugin marketplace update garde-secrets
claude plugin update garde-secrets@garde-secrets
claude plugin disable garde-secrets@garde-secrets
```

(Installé par copie du dossier : remplace le dossier ; l'identifiant est alors `garde-secrets@skills-dir`.)
