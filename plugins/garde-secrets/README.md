# garde-secrets

Plugin pour Claude Code. Il bloque, **avant exécution**, ce qui ferait sortir un secret de ta machine :
Claude ne peut plus lire ni afficher un fichier secret, ni imprimer un jeton, ni commiter une clé.

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

Pour le banc d'essai complet : `claude plugin test <dossier du plugin>` (module intégré) et
`python3 tests/cas.py` (secours Python, doit finir par `0 échec`). Les deux lisent les mêmes cas.

## Ce qui est bloqué

| Situation | Exemples |
|---|---|
| Lire ou afficher un fichier secret | `.env`, `*.key`, `*.pem`, clés SSH (`id_rsa`, `id_ed25519`…), `*.p12`, `*.kdbx`, `~/.aws/credentials`, `~/.netrc`, `~/.kube/config`, dossiers `secrets/` |
| Terraform / OpenTofu | lecture de `*.tfstate`, `*.tfvars`, plans enregistrés ; `terraform show`, `state pull`, `state show`, `console`, `output -json`, `output -raw`, `output <nom>`, `TF_LOG=DEBUG` |
| Afficher des variables d'environnement | `env`, `printenv`, `export -p`, `echo $MON_TOKEN` ; sous PowerShell : `Get-ChildItem Env:`, `echo $env:MON_TOKEN` |
| Commandes qui impriment un secret | `gh auth token`, `gcloud auth print-access-token`, `aws configure get`, `vault kv get`, `kubectl get secret -o yaml`, `docker inspect`, `docker compose config` |
| Faire entrer un secret dans git | `git add` ou `git commit` d'un fichier secret, ou d'un contenu reconnu : clé privée, clé AWS, jeton GitHub/GitLab/Slack, clé d'API, JWT, mot de passe écrit en dur, identifiants dans une URL |

Le message de refus nomme le fichier ou la variable, jamais la valeur.

## Ce qui reste permis

- Copier, déplacer, supprimer un fichier secret ; lire sa taille et ses droits (`ls`, `stat`).
- Comparer des empreintes : `sha256sum < fichier`.
- Utiliser un secret sans l'afficher : `curl -H "Authorization: Bearer $API_TOKEN" …`, `ssh -i ~/.ssh/id_ed25519 …`, `docker run --env-file .env …`.
- Les fichiers modèles : `.env.example`, `*.tfvars.example`, `*.sample`, `*.template`.
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
- Le contrôle des commits reconnaît des formes connues de secrets. Un secret sans forme reconnaissable
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
