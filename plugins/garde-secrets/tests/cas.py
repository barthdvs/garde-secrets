#!/usr/bin/env python3
"""Banc d'essai de garde-secrets : python3 tests/cas.py (doit finir par « 0 échec »).

Les faux secrets sont assemblés par morceaux pour que ce fichier ne contienne lui-même aucun motif de secret.
"""
import json, subprocess, os, sys, tempfile
G = os.path.join(os.path.dirname(__file__), "..", "hooks-handlers", "garde.py")

# Cas communs aux deux moteurs : ce qui suit « export const CAS = » dans cas-communs.ts est du JSON.
with open(os.path.join(os.path.dirname(__file__), "cas-communs.ts"), encoding="utf-8") as f:
    CAS = json.loads(f.read().split("export const CAS = ", 1)[1])
REFUS, PASSE, REFUS_PERSO = CAS["refus"], CAS["passe"], CAS["refusPerso"]

# Faux secrets, assemblés pour ne pas figurer tels quels dans ce fichier
F_GITHUB = "gh" + "p_" + "a1B2" * 9
F_AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
F_CLE = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIfaux\n"
F_MDP = 'pass' + 'word = "Xk29fjdk20dkfj3"\n'
F_YAML = 'api_' + 'key: 9f8e7d6c5b4a39281706f5e4\n'  # gitleaks:allow (faux secret du banc d'essai)
F_URL = "DATABASE_URL=postgres://appli:" + "s3cretMdp42" + "@db.example.com/base\n"


def decision(outil, entree, motifs, cwd=None):
    if isinstance(entree, str): entree = {"command": entree}
    env = dict(os.environ, GARDE_SECRETS_MOTIFS=motifs)
    ev = {"tool_name": outil, "tool_input": entree}
    if cwd: ev["cwd"] = cwd
    r = subprocess.run([sys.executable, G], input=json.dumps(ev), capture_output=True, text=True, timeout=30, env=env)
    out = r.stdout.strip()
    if not out: return "passe", ""
    h = json.loads(out)["hookSpecificOutput"]
    return ("refus" if h["permissionDecision"] == "deny" else "passe"), h.get("permissionDecisionReason", "")


def g(rep, *args):
    subprocess.run(["git", "-C", rep, "-c", "user.name=essai", "-c", "user.email=essai@example.com"] + list(args),
                   check=True, capture_output=True)


def ecrire(rep, nom, contenu):
    chemin = os.path.join(rep, nom)
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(chemin, "w", encoding="utf-8") as f:
        f.write(contenu)


total = echecs = 0


def attendu(voulu, outil, e, motifs, cwd=None, etiquette="", interdit=None):
    global total, echecs
    total += 1
    d, raison = decision(outil, e, motifs, cwd)
    if d != voulu:
        echecs += 1; print("ÉCHEC (devait %s) %s:" % ("refuser" if voulu == "refus" else "passer", etiquette), outil, str(e)[:110])
    elif interdit and interdit in raison:
        echecs += 1; print("ÉCHEC (le message de refus contient la valeur du secret) :", etiquette)


with tempfile.TemporaryDirectory() as d:
    vide = os.path.join(d, "absent.txt")  # aucun motif personnel
    perso = os.path.join(d, "motifs.txt")
    with open(perso, "w", encoding="utf-8") as f:
        f.write("# essai\nclients\\.csv$\n(motif invalide\n")
    for outil, e in REFUS: attendu("refus", outil, e, vide)
    for outil, e in PASSE: attendu("passe", outil, e, vide)
    for outil, e in REFUS_PERSO: attendu("refus", outil, e, perso, etiquette="motif personnel")

    # git add / git commit sur un vrai dépôt jetable
    rep = os.path.join(d, "depot")
    os.makedirs(rep)
    g(rep, "init", "-q")
    ecrire(rep, "README.md", "# essai\n")
    ecrire(rep, "main.tf", 'variable "db_password" {\n  sensitive = true\n}\nresource "x" "y" {\n  password = var.db_password\n  token_url = "https://auth.example.com/oauth2/token"\n  api_key = "${var.api_key}"\n}\n')
    attendu("passe", "Bash", "git add .", vide, rep, "add propre")
    g(rep, "add", "."); g(rep, "commit", "-q", "-m", "init")
    attendu("passe", "Bash", "git commit -m 'rien de neuf'", vide, rep, "commit vide")

    for nom, contenu, valeur in [("config.py", "JETON = '%s'\n" % F_GITHUB, F_GITHUB), ("deploy.sh", "export CLE=%s\n" % F_AWS, F_AWS),
                                 ("cle.txt", F_CLE, None), ("settings.py", F_MDP, "Xk29fjdk20dkfj3"),
                                 ("values.yaml", F_YAML, "9f8e7d6c5b4a39281706f5e4"), ("compose.yaml", F_URL, "s3cretMdp42")]:
        ecrire(rep, nom, contenu)
        attendu("refus", "Bash", "git add .", vide, rep, "add " + nom, interdit=valeur)
        attendu("refus", "Bash", "git add %s && git commit -m x" % nom, vide, rep, "add+commit " + nom, interdit=valeur)
        attendu("passe", "Bash", "git add README.md", vide, rep, "add d'un autre fichier que " + nom)
        g(rep, "add", nom)
        attendu("refus", "Bash", "git commit -m x", vide, rep, "commit " + nom, interdit=valeur)
        attendu("refus", "Bash", "git -C %s commit -m x" % rep, vide, d, "commit -C " + nom, interdit=valeur)
        attendu("refus", "Bash", "cd depot && git commit -m x", vide, d, "cd puis commit " + nom, interdit=valeur)
        g(rep, "rm", "-q", "--cached", nom); os.remove(os.path.join(rep, nom))

    # fichier secret par son nom, même forcé ; état Terraform
    ecrire(rep, ".env", "A=1\n"); ecrire(rep, "infra/terraform.tfstate", "{}\n")
    attendu("refus", "Bash", "git add -f .env", vide, rep, "add -f .env")
    attendu("refus", "Bash", "git add infra", vide, rep, "add tfstate")
    g(rep, "add", "-f", ".env")
    attendu("refus", "Bash", "git commit -m x", vide, rep, "commit .env")
    g(rep, "rm", "-q", "--cached", ".env"); os.remove(os.path.join(rep, ".env")); os.remove(os.path.join(rep, "infra/terraform.tfstate"))

    # modification non indexée d'un fichier suivi : seul « commit -a » la prend
    ecrire(rep, "README.md", "# essai\njeton : %s\n" % F_GITHUB)
    attendu("passe", "Bash", "git commit -m x", vide, rep, "commit sans -a")
    attendu("refus", "Bash", "git commit -am x", vide, rep, "commit -am", interdit=F_GITHUB)
    attendu("refus", "Bash", "git commit --all -m x", vide, rep, "commit --all", interdit=F_GITHUB)
    ecrire(rep, "README.md", "# essai\nligne anodine\n")
    attendu("passe", "Bash", "git commit -am 'doc'", vide, rep, "commit -am propre")

print("%d cas, %d échec" % (total, echecs))
sys.exit(1 if echecs else 0)
