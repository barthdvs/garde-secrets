#!/usr/bin/env python3
"""garde-secrets — hook PreToolUse de Claude Code (secours Python).

Même logique et mêmes listes que hooks/garde.ts, le module que Claude Code exécute lui-même.
Ce script sert aux versions de Claude Code qui ne chargent pas ce module ; toute règle changée
ici l'est aussi là-bas, et tests/cas-communs.ts vérifie les deux.

Refuse, AVANT exécution, tout appel d'outil qui ferait sortir un secret :
  - Read / Grep / Edit sur un chemin secret ;
  - commande Bash où un fichier secret est passé à une commande d'affichage (cat, grep, head,
    openssl, file, xxd…), y compris dans `ssh … '…'`, `sh -c '…'`, `docker exec … sh -c '…'` ;
  - commandes qui impriment un secret : `terraform show`, `terraform state pull`, `terraform output -json`,
    `env`, `echo $TOKEN`, `gh auth token`, `kubectl get secret -o yaml`… ;
  - `git add` / `git commit` qui feraient entrer dans le dépôt un fichier secret ou un contenu
    reconnu comme secret (clé privée, jeton, mot de passe affecté en dur).
Restent permis : copier (`cat > f`, `ssh … < f`), détruire (`shred`), métadonnées (`stat`, `ls`),
empreintes (`… | sha256sum`), substitution `$(…)` qui ne s'affiche pas (`printf … > f`).

Pas de contournement prévu : pour l'arrêter, l'utilisateur désactive le plugin
(`claude plugin disable garde-secrets@<source>`, la source est donnée par `claude plugin list`).

Motifs personnels : une expression régulière par ligne dans ~/.config/garde-secrets/motifs.txt
(ou le fichier désigné par GARDE_SECRETS_MOTIFS). Ils s'ajoutent à la liste, ils n'en retirent rien.
"""
import json, os, re, shlex, subprocess, sys

# Chemins considérés comme secrets (testés sur chaque mot de la commande / chaque chemin d'outil)
SECRETS = [
    # clés et certificats privés
    r"\.key$", r"\.pem$", r"(^|/)rsa_key",
    r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(_[^/\s.]*)?$", r"\.(p12|pfx|jks|keystore|kdbx)$",
    # fichiers d'environnement et d'identifiants
    r"(^|/)\.env($|\.)", r"(^|/)[^/\s]*\.env$", r"^/proc/[^/]+/environ$",
    r"(^|/)\.(netrc|pgpass|pypirc|git-credentials|vault-token|htpasswd)$",
    r"(^|/)\.aws/credentials$", r"(^|/)\.docker/config\.json$", r"(^|/)\.kube/config$",
    r"(^|/)(role_id|secret_id)$", r"(admin|root)-password$",
    r"/secrets?/", r"\.secret$", r"/\.config/[^/]+/token$", r"sasl_passwd", r"ssmtp\.conf",
    # Terraform / OpenTofu : état, variables, plans enregistrés, identifiants du CLI
    r"\.tfstate($|\.)", r"\.tfvars($|\.json$)", r"\.tfplan$", r"(^|/)tfplan[^/]*$",
    r"(^|/)\.terraformrc$", r"(^|/)terraform\.rc$", r"credentials\.tfrc\.json$",
]
# Modèles sans valeur réelle (.env.example…) : jamais secrets
EXEMPLES_RE = re.compile(r"\.(example|sample|template|tmpl|dist)$")

# Secrets reconnaissables dans un contenu (contrôle de git add / git commit)
JETONS = [
    ("clé privée", r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    ("clé d'accès AWS", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("jeton GitHub", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    ("jeton GitLab", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("jeton Slack", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("webhook Slack", r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ("clé API Anthropic", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("clé API OpenAI", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    ("clé API Google", r"\bAIza[0-9A-Za-z_-]{35}"),
    ("clé Stripe", r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
    ("jeton Vault", r"\bhv[sbr]\.[A-Za-z0-9_-]{24,}"),
    ("jeton npm", r"\bnpm_[A-Za-z0-9]{36}"),
    ("clé d'accès Scaleway", r"\bSCW[A-Z0-9]{17}\b"),
    ("jeton JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
]
JETONS_RE = [(n, re.compile(p)) for n, p in JETONS]
URL_IDENTIFIANTS = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:([^/\s:@'\"]{6,})@")
_CLE = r"([\w.-]{0,40}(?:passw(?:or)?d|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[\w.-]{0,40})"
AFFECTATIONS = [
    re.compile(r"(?i)" + _CLE + r"[\"']?\s*[:=]\s*[\"']([^\"'\s]{12,})[\"']"),
    re.compile(r"(?im)" + _CLE + r"[\"']?\s*[:=]\s*([A-Za-z0-9+/=_-]{16,})\s*$"),
]
CLE_ANODINE = re.compile(r"(?i)[_.-](url|uri|path|file|name|id|endpoint|type|ttl|length|size|expir\w*|header|field|prefix)$")
FACTICE = re.compile(r"(?i)[${}<>*]|change|example|exemple|placeholder|dummy|your|votre|redacted|todo|^[a-z]+://|^[/~.]")

# Variables d'environnement dont le nom annonce un secret
VAR_SECRETE = re.compile(r"(?i)\$(?:env:|\{)?\w*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)\w*")
NOM_SECRET = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)")
TF_LOG = re.compile(r"(?i)^TF_LOG(_CORE|_PROVIDER)?=(trace|debug)$")
TERRAFORM = {"terraform", "tofu", "terragrunt"}
# Commandes qui impriment un secret sur la sortie
IMPRIME_SECRET = [
    (r"^gh auth token\b", "« gh auth token » affiche le jeton GitHub"),
    (r"^gcloud auth (application-default )?print-(access|identity)-token\b", "« gcloud auth print-…-token » affiche un jeton"),
    (r"^az account get-access-token\b", "« az account get-access-token » affiche un jeton"),
    (r"^aws configure (get|export-credentials)\b", "« aws configure » afficherait des identifiants"),
    (r"^aws sts (get-session-token|assume-role\S*)\b", "« aws sts » affiche des identifiants temporaires"),
    (r"^aws secretsmanager get-secret-value\b", "« aws secretsmanager get-secret-value » affiche un secret"),
    (r"^aws ssm get-parameters?\b.*--with-decryption", "« aws ssm … --with-decryption » affiche un secret"),
    (r"^(vault|bao) (kv get|read|token create|login)\b", "cette commande affiche un secret du coffre"),
    (r"^kubectl\b.*\bget secrets?\b.*-o ?(yaml|json|jsonpath|go-template)", "« kubectl get secret -o … » affiche le contenu du secret"),
    (r"^docker (compose )?config\b", "« docker compose config » affiche les variables d'environnement résolues"),
    (r"^docker (compose )?exec\b.* (env|printenv)$", "cette commande affiche l'environnement du conteneur"),
    (r"^security find-(generic|internet)-password\b.* -w", "cette commande affiche un mot de passe du trousseau"),
    (r"^op read\b", "« op read » affiche un secret 1Password"),
]
IMPRIME_SECRET_RE = [(re.compile(p), r) for p, r in IMPRIME_SECRET]

CONSEIL_GIT = ("Rien n'a été ajouté ni commité. Retire ces éléments de l'index (git restore --staged), "
               "ajoute-les au .gitignore ou remplace la valeur par une variable. Si c'est un faux positif, "
               "c'est à l'utilisateur de faire ce commit lui-même dans son terminal.")


def motifs_perso():
    chemin = os.environ.get("GARDE_SECRETS_MOTIFS") or os.path.join(
        os.path.expanduser("~"), ".config", "garde-secrets", "motifs.txt")
    res = []
    try:
        with open(chemin, encoding="utf-8") as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne or ligne.startswith("#"): continue
                try:
                    res.append(re.compile(ligne))
                except re.error:
                    pass
    except OSError:
        pass
    return res


SECRETS_RE = [re.compile(p) for p in SECRETS] + motifs_perso()

# Commandes qui affichent ou interprètent le contenu d'un fichier
AFFICHAGE = {
    "cat", "tac", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "zgrep", "sed", "awk",
    "gawk", "cut", "strings", "xxd", "od", "hexdump", "file", "openssl", "base64", "jq", "yq", "diff", "cmp",
    "vi", "vim", "nano", "tr", "nl", "fold", "column", "sort", "uniq", "paste", "rev", "iconv", "zcat",
    "bat", "view", "pr", "expand", "tee", "dd", "xargs",
    # Windows / PowerShell
    "type", "get-content", "gc", "select-string", "sls", "findstr", "format-hex",
}
# Puits sûrs : ce qui reçoit le contenu sans l'afficher
PUITS = {"sha256sum", "sha1sum", "md5sum", "b2sum", "wc", "ssh", "scp", "docker", "curl", "shred",
         "install", "true", "openssl-dgst"}
ENVELOPPES = {"sudo", "env", "timeout", "nice", "nohup", "setsid", "exec", "time", "command", "stdbuf"}
LISTE_ENV = {"gci", "dir", "ls", "get-childitem", "get-item"}
REP = [os.getcwd()]  # dossier courant de la commande analysée (suit les « cd »)
POWERSHELL = [False]


def est_secret(mot):
    m = mot.strip("'\"").replace("\\", "/")  # chemins Windows
    if EXEMPLES_RE.search(m): return False
    return any(r.search(m) for r in SECRETS_RE)


def trouver_secrets(texte):
    """Noms des secrets reconnus dans un contenu — jamais leur valeur."""
    noms = [nom for nom, rx in JETONS_RE if rx.search(texte)]
    if any(not FACTICE.search(m.group(1)) for m in URL_IDENTIFIANTS.finditer(texte)):
        noms.append("identifiants dans une URL")
    for rx in AFFECTATIONS:
        for m in rx.finditer(texte):
            cle, val = m.group(1), m.group(2)
            if CLE_ANODINE.search(cle) or FACTICE.search(val): continue
            if not (re.search(r"[A-Za-z]", val) and re.search(r"[0-9]", val)): continue
            noms.append("valeur en dur pour « %s »" % cle[:40])
            return noms
    return noms


def premier_mot(toks):
    i = 0
    while i < len(toks):
        t = toks[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            i += 1; continue
        if t in ENVELOPPES:
            i += 1
            if t == "timeout" and i < len(toks) and re.match(r"^[0-9.]+[smhd]?$", toks[i]):
                i += 1
            continue
        nom = re.sub(r"(?i)\.exe$", "", t.rsplit("/", 1)[-1])
        return i, (nom.lower() if POWERSHELL[0] else nom)
    return None, ""


def decouper(cmd, seps):
    """Découpe hors guillemets sur les séparateurs donnés."""
    out, cur, q, i = [], "", None, 0
    while i < len(cmd):
        c = cmd[i]
        if q:
            cur += c
            if c == q: q = None
            elif c == "\\" and q == '"' and i + 1 < len(cmd): cur += cmd[i + 1]; i += 1
        elif c in "'\"":
            q = c; cur += c
        else:
            hit = next((s for s in seps if cmd.startswith(s, i)), None)
            if hit:
                out.append(cur); cur = ""; i += len(hit); continue
            cur += c
        i += 1
    out.append(cur)
    return [s.strip() for s in out if s.strip()]


def substitutions(cmd):
    """Contenu des $( … ) (un niveau)."""
    res, i = [], 0
    while True:
        j = cmd.find("$(", i)
        if j < 0: return res
        prof, k = 1, j + 2
        while k < len(cmd) and prof:
            prof += {"(": 1, ")": -1}.get(cmd[k], 0); k += 1
        res.append(cmd[j + 2:k - 1]); i = k


def git(rep, *args):
    try:
        r = subprocess.run(["git", "-C", rep] + list(args), capture_output=True, text=True,
                           errors="replace", timeout=8)
        return r.stdout[:4000000] if r.returncode == 0 else ""
    except Exception:
        return ""


def examiner_fichiers(rep, chemins):
    """Fichiers qu'un « git add » ferait entrer : nom secret, ou contenu reconnu."""
    res = []
    for c in chemins[:2000]:
        if est_secret(c):
            res.append("%s (fichier secret)" % c); continue
        try:
            with open(os.path.join(rep, c), "rb") as f:
                brut = f.read(1000000)
        except OSError:
            continue
        if b"\0" in brut: continue
        noms = trouver_secrets(brut.decode("utf-8", "replace"))
        if noms: res.append("%s (%s)" % (c, ", ".join(noms)))
    return res


def examiner_diff(diff):
    """Lignes ajoutées d'un diff, regroupées par fichier."""
    res, fichier, ajouts = [], None, {}
    for ligne in diff.splitlines():
        if ligne.startswith("+++ "):
            fichier = ligne[6:] if ligne[4:6] == "b/" else None
        elif ligne.startswith("+") and fichier:
            ajouts.setdefault(fichier, []).append(ligne[1:])
    for f, lignes in ajouts.items():
        noms = trouver_secrets("\n".join(lignes))
        if noms: res.append("%s (%s)" % (f, ", ".join(noms)))
    return res


def controle_git(args, visible):
    """Renvoie une raison de refus pour une commande git, ou None."""
    rep, i = REP[0], 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            rep = os.path.normpath(os.path.join(rep, os.path.expanduser(args[i + 1]))); i += 2; continue
        i += 2 if args[i] == "-c" else 1
    if i >= len(args): return None
    sub, reste = args[i], args[i + 1:]
    if sub in ("show", "diff", "blame", "cat-file", "grep") or (
            sub == "log" and any(a in ("-p", "-u", "--patch") for a in reste)):
        vus = sorted({p for a in reste for p in a.split(":") if p and est_secret(p)})
        if visible and vus:
            return "« git %s » afficherait le contenu de %s" % (sub, ", ".join(vus))
        return None
    if sub == "add":
        sans_dialogue = [a for a in reste if a not in ("-p", "-i", "-e", "--patch", "--interactive", "--edit")]
        sortie = git(rep, "add", "--dry-run", *sans_dialogue)
        chemins = re.findall(r"^add '(.*)'$", sortie, re.M)
        trouvailles = examiner_fichiers(rep, chemins)
    elif sub == "commit":
        tout = any(a == "--all" or re.match(r"^-[A-Za-z]*a[A-Za-z]*$", a) for a in reste)
        noms = git(rep, "diff", "--cached", "--name-only", "--diff-filter=ACMR").split("\n")
        diff = git(rep, "diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR")
        if tout:
            noms += git(rep, "diff", "--name-only", "--diff-filter=ACMR").split("\n")
            diff += "\n" + git(rep, "diff", "-U0", "--no-color", "--diff-filter=ACMR")
        secrets = sorted({n for n in noms if n and est_secret(n)})
        trouvailles = ["%s (fichier secret)" % n for n in secrets]
        trouvailles += [t for t in examiner_diff(diff) if t.split(" (")[0] not in secrets]
    else:
        return None
    if trouvailles:
        plus = " ; … (%d autres)" % (len(trouvailles) - 8) if len(trouvailles) > 8 else ""
        return "« git %s » ferait entrer des secrets dans le dépôt : %s%s. %s" % (
            sub, " ; ".join(trouvailles[:8]), plus, CONSEIL_GIT)
    return None


def controle_terraform(mot, args):
    pos = [a for a in args if not a.startswith("-") and a not in ("run-all", "run")]
    opts = {a.lstrip("-").split("=")[0] for a in args if a.startswith("-")}
    if not pos: return None
    sub, reste = pos[0], pos[1:]
    if sub == "show":
        return "« %s show » affiche l'état ou le plan en entier, valeurs sensibles comprises" % mot
    if sub == "console":
        return "« %s console » donne accès à toutes les valeurs de l'état" % mot
    if sub == "state" and reste[:1] and reste[0] in ("pull", "show"):
        return "« %s state %s » affiche l'état, valeurs sensibles comprises" % (mot, reste[0])
    if sub == "output" and (reste or opts & {"json", "raw"}):
        return ("« %s output » avec un nom, -json ou -raw affiche les sorties sensibles en clair "
                "(sans argument, elles restent masquées)" % mot)
    return None


def controle_env(mot, args, ligne):
    """Commandes qui affichent des variables d'environnement ou impriment un secret."""
    if mot in ("echo", "printf", "write-output", "write-host"):
        vus = sorted({m.group(0) for a in args for m in VAR_SECRETE.finditer(a)})
        if vus: return "« %s » afficherait la valeur de %s" % (mot, ", ".join(vus))
    if re.match(r"(?i)^\$env:", mot) and NOM_SECRET.search(mot):
        return "cette commande afficherait la valeur de %s" % mot
    if mot == "printenv":
        noms = [a for a in args if not a.startswith("-")]
        if not noms or any(NOM_SECRET.search(a) for a in noms):
            return "« printenv » afficherait des variables secrètes (demande une variable précise et anodine : printenv NOM)"
    if (mot == "set" and not args) or (mot == "export" and args in ([], ["-p"])) or (
            mot == "declare" and args and all(a in ("-p", "-x", "-px", "-xp") for a in args)) or (
            mot in LISTE_ENV and any(re.match(r"(?i)^env:", a) for a in args)):
        return "« %s » afficherait toutes les variables d'environnement, jetons compris" % mot
    if mot == "docker" and re.match(r"^docker inspect\b", ligne):
        if not re.search(r" (--format|-f)[ =]", ligne) or re.search(r"Env|Config\b", ligne):
            return "« docker inspect » sans --format ciblé affiche les variables d'environnement du conteneur"
    for rx, raison in IMPRIME_SECRET_RE:
        if rx.search(ligne): return raison
    return None


def analyser(cmd, affiche=True, profondeur=0, local=True):
    """Renvoie une raison de refus, ou None."""
    if profondeur > 4: return None
    # Les $( … ) : leur sortie va à la commande englobante.
    for sub in substitutions(cmd):
        r = analyser(sub, affiche=False, profondeur=profondeur + 1, local=local)
        if r: return r
    sans_sub = re.sub(r"\$\((?:[^()]|\([^()]*\))*\)", "SUBST", cmd)
    for seg in decouper(sans_sub, ["&&", "||", ";", "\n"]):
        etapes = decouper(seg, ["|"])
        for n, etape in enumerate(etapes):
            try:
                toks = shlex.split(etape, comments=False)
            except ValueError:
                toks = etape.split()
            if any(TF_LOG.match(t) for t in toks):
                return "TF_LOG=TRACE/DEBUG écrit les échanges avec les fournisseurs, identifiants compris"
            i, mot = premier_mot(toks)
            redirige = re.search(r"(^|[^<0-9&])>{1,2}\s*[^&\s]", etape) and not re.search(r"\b(tee)\b", etape)
            suite = etapes[n + 1:]
            vers_puits = suite and all(premier_mot(s.split())[1] in PUITS for s in suite[:1])
            visible = affiche and not redirige and not vers_puits
            if i is None:
                if visible and "env" in toks:
                    return "« env » afficherait toutes les variables d'environnement, jetons compris"
                continue
            args = toks[i + 1:]
            if mot == "cd" and args and local:
                REP[0] = os.path.normpath(os.path.join(REP[0], os.path.expanduser(args[0])))
            # Commandes distantes ou enveloppées : on analyse la chaîne qu'elles exécutent.
            if mot in ("ssh",):
                distante = [a for a in args if " " in a or ";" in a or "|" in a]
                for d in distante[-1:]:
                    r = analyser(d, affiche=affiche and n == len(etapes) - 1, profondeur=profondeur + 1, local=False)
                    if r: return r
            # Toute chaîne passée par « -c » (sh -c, bash -c, $D run … sh -c, chroot … sh -c…) est analysée.
            if mot != "git":
                for k, a in enumerate(args):
                    if a == "-c" and k + 1 < len(args):
                        r = analyser(args[k + 1], affiche=affiche and n == len(etapes) - 1, profondeur=profondeur + 1,
                                     local=local and mot in ("sh", "bash", "zsh", "dash"))
                        if r: return r
            if mot == "git" and local:
                r = controle_git(args, visible)
                if r: return r
            if mot in TERRAFORM and affiche and not vers_puits:
                r = controle_terraform(mot, args)
                if r: return r
            if visible:
                r = controle_env(mot, args, " ".join([mot] + args))
                if r: return r
            if mot not in AFFICHAGE: continue
            # Fichiers secrets lus par cette étape (hors redirection de sortie « > f »)
            lus, prec = [], ""
            for a in args:
                if prec in (">", ">>", "2>", "&>") or a.startswith(">"):
                    prec = a; continue
                if a.startswith("<") and len(a) > 1: a = a[1:]
                if est_secret(a): lus.append(a)
                prec = a
            if not lus: continue
            if mot == "sed" and any(a.startswith("-i") for a in args) and not any(a in ("-n",) for a in args):
                continue  # édition en place sans affichage
            if not visible:
                continue
            return "« %s » afficherait le contenu de %s" % (mot, ", ".join(sorted(set(lus))))
    return None


def refuser(raison):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "garde-secrets : " + raison + ". Un secret ne doit être ni lu, ni affiché, "
        "ni commité. Restent permis : copier le fichier, le supprimer, lire ses métadonnées (stat, ls), "
        "comparer son empreinte (sha256sum). Ne cherche pas un autre moyen d'y arriver : dis à l'utilisateur "
        "ce qui a été refusé. Si le blocage est une erreur, c'est à lui de faire l'opération ou de "
        "désactiver le plugin garde-secrets."}}))
    sys.exit(0)


def main():
    try:
        ev = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    outil, entree = ev.get("tool_name", ""), ev.get("tool_input", {}) or {}
    if ev.get("cwd"): REP[0] = ev["cwd"]
    if outil in ("Read", "Edit", "MultiEdit", "NotebookEdit"):
        p = entree.get("file_path") or entree.get("notebook_path") or ""
        if est_secret(p): refuser("lecture de %s par %s" % (p, outil))
    elif outil == "Grep":
        for p in (entree.get("path") or "", entree.get("glob") or ""):
            if p and est_secret(p): refuser("recherche dans %s" % p)
    elif outil in ("Bash", "PowerShell"):
        cmd = entree.get("command", "")
        if outil == "PowerShell":
            POWERSHELL[0] = True
            cmd = cmd.replace("\\", "/")  # l'antislash n'y est pas un échappement
        try:
            r = analyser(cmd)
        except Exception:
            # En cas de doute (analyse impossible) : refus si un verbe d'affichage côtoie un chemin secret.
            mots = re.findall(r"[^\s'\";|&()<>]+", cmd)
            r = ("commande non analysable mêlant affichage et fichier secret"
                 if any(re.sub(r"(?i)\.exe$", "", m.rsplit("/", 1)[-1]) in AFFICHAGE for m in mots) and any(est_secret(m) for m in mots) else None)
        if r: refuser(r)
    sys.exit(0)


if __name__ == "__main__":
    main()
