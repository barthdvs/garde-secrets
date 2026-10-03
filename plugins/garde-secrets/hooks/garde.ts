// garde-secrets — module de crochets exécuté par Claude Code lui-même (rien à installer).
//
// Refuse, AVANT exécution, tout appel d'outil qui ferait sortir un secret : lecture ou affichage
// d'un fichier secret, commande qui imprime un jeton ou l'état Terraform, `git add` / `git commit`
// d'un secret. Même logique et mêmes listes que hooks-handlers/garde.py (secours Python pour les
// versions de Claude Code qui ne chargent pas ce module) : toute règle changée ici l'est aussi là-bas,
// et tests/cas-communs.ts vérifie les deux.
import type { EngineInterface, Register } from 'claude-code'

// Chemins considérés comme secrets (testés sur chaque mot de la commande / chaque chemin d'outil)
const SECRETS = [
  // clés et certificats privés
  String.raw`\.key$`, String.raw`\.pem$`, String.raw`(^|/)rsa_key`,
  String.raw`(^|/)id_(rsa|dsa|ecdsa|ed25519)(_[^/\s.]*)?$`, String.raw`\.(p12|pfx|jks|keystore|kdbx)$`,
  // fichiers d'environnement et d'identifiants
  String.raw`(^|/)\.env($|\.)`, String.raw`(^|/)[^/\s]*\.env$`, String.raw`^/proc/[^/]+/environ$`,
  String.raw`(^|/)\.(netrc|pgpass|pypirc|git-credentials|vault-token|htpasswd)$`,
  String.raw`(^|/)\.aws/credentials$`, String.raw`(^|/)\.docker/config\.json$`, String.raw`(^|/)\.kube/config$`,
  String.raw`(^|/)(role_id|secret_id)$`, String.raw`(admin|root)-password$`,
  String.raw`/secrets?/`, String.raw`\.secret$`, String.raw`/\.config/[^/]+/token$`, 'sasl_passwd', String.raw`ssmtp\.conf`,
  // Terraform / OpenTofu : état, variables, plans enregistrés, identifiants du CLI
  String.raw`\.tfstate($|\.)`, String.raw`\.tfvars($|\.json$)`, String.raw`\.tfplan$`, String.raw`(^|/)tfplan[^/]*$`,
  String.raw`(^|/)\.terraformrc$`, String.raw`(^|/)terraform\.rc$`, String.raw`credentials\.tfrc\.json$`,
].map(p => new RegExp(p))
// Modèles sans valeur réelle (.env.example…) : jamais secrets
const EXEMPLES = /\.(example|sample|template|tmpl|dist)$/

// Secrets reconnaissables dans un contenu (contrôle de git add / git commit)
const JETONS: [string, RegExp][] = [
  ['clé privée', /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/],
  ["clé d'accès AWS", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['jeton GitHub', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/],
  ['jeton GitLab', /\bglpat-[A-Za-z0-9_-]{20,}/],
  ['jeton Slack', /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
  ['webhook Slack', /hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/],
  ['clé API Anthropic', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['clé API OpenAI', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
  ['clé API Google', /\bAIza[0-9A-Za-z_-]{35}/],
  ['clé Stripe', /\b[sr]k_live_[A-Za-z0-9]{20,}/],
  ['jeton Vault', /\bhv[sbr]\.[A-Za-z0-9_-]{24,}/],
  ['jeton npm', /\bnpm_[A-Za-z0-9]{36}/],
  ["clé d'accès Scaleway", /\bSCW[A-Z0-9]{17}\b/],
  ['jeton JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
]
const URL_IDENTIFIANTS = String.raw`[a-z][a-z0-9+.-]*://[^/\s:@'"]+:([^/\s:@'"]{6,})@`
const CLE = String.raw`([\w.-]{0,40}(?:passw(?:or)?d|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[\w.-]{0,40})`
const AFFECTATIONS: [string, string][] = [
  [CLE + String.raw`["']?\s*[:=]\s*["']([^"'\s]{12,})["']`, 'gi'],
  [CLE + String.raw`["']?\s*[:=]\s*([A-Za-z0-9+/=_-]{16,})\s*$`, 'gim'],
]
const CLE_ANODINE = /[_.-](url|uri|path|file|name|id|endpoint|type|ttl|length|size|expir\w*|header|field|prefix)$/i
const FACTICE = /[${}<>*]|change|example|exemple|placeholder|dummy|your|votre|redacted|todo|^[a-z]+:\/\/|^[/~.]/i

// Variables d'environnement dont le nom annonce un secret
const VAR_SECRETE = String.raw`\$(?:env:|\{)?\w*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)\w*`
const NOM_SECRET = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)/i
const TF_LOG = /^TF_LOG(_CORE|_PROVIDER)?=(trace|debug)$/i
const TERRAFORM = new Set(['terraform', 'tofu', 'terragrunt'])
// Commandes qui impriment un secret sur la sortie
const IMPRIME_SECRET: [RegExp, string][] = [
  [/^gh auth token\b/, '« gh auth token » affiche le jeton GitHub'],
  [/^gcloud auth (application-default )?print-(access|identity)-token\b/, '« gcloud auth print-…-token » affiche un jeton'],
  [/^az account get-access-token\b/, '« az account get-access-token » affiche un jeton'],
  [/^aws configure (get|export-credentials)\b/, '« aws configure » afficherait des identifiants'],
  [/^aws sts (get-session-token|assume-role\S*)/, '« aws sts » affiche des identifiants temporaires'],
  [/^aws secretsmanager get-secret-value\b/, '« aws secretsmanager get-secret-value » affiche un secret'],
  [/^aws ssm get-parameters?\b.*--with-decryption/, '« aws ssm … --with-decryption » affiche un secret'],
  [/^(vault|bao) (kv get|read|token create|login)\b/, 'cette commande affiche un secret du coffre'],
  [/^kubectl\b.*\bget secrets?\b.*-o ?(yaml|json|jsonpath|go-template)/, '« kubectl get secret -o … » affiche le contenu du secret'],
  [/^docker (compose )?config\b/, "« docker compose config » affiche les variables d'environnement résolues"],
  [/^docker (compose )?exec\b.* (env|printenv)$/, "cette commande affiche l'environnement du conteneur"],
  [/^security find-(generic|internet)-password\b.* -w/, 'cette commande affiche un mot de passe du trousseau'],
  [/^op read\b/, '« op read » affiche un secret 1Password'],
]

const CONSEIL_GIT =
  "Rien n'a été ajouté ni commité. Retire ces éléments de l'index (git restore --staged), " +
  'ajoute-les au .gitignore ou remplace la valeur par une variable. Si c\'est un faux positif, ' +
  "c'est à l'utilisateur de faire ce commit lui-même dans son terminal."

// Commandes qui affichent ou interprètent le contenu d'un fichier
const AFFICHAGE = new Set([
  'cat', 'tac', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'zgrep', 'sed', 'awk',
  'gawk', 'cut', 'strings', 'xxd', 'od', 'hexdump', 'file', 'openssl', 'base64', 'jq', 'yq', 'diff', 'cmp',
  'vi', 'vim', 'nano', 'tr', 'nl', 'fold', 'column', 'sort', 'uniq', 'paste', 'rev', 'iconv', 'zcat',
  'bat', 'view', 'pr', 'expand', 'tee', 'dd', 'xargs',
  // Windows / PowerShell
  'type', 'get-content', 'gc', 'select-string', 'sls', 'findstr', 'format-hex',
])
// Puits sûrs : ce qui reçoit le contenu sans l'afficher
const PUITS = new Set(['sha256sum', 'sha1sum', 'md5sum', 'b2sum', 'wc', 'ssh', 'scp', 'docker', 'curl', 'shred',
  'install', 'true', 'openssl-dgst'])
const ENVELOPPES = new Set(['sudo', 'env', 'timeout', 'nice', 'nohup', 'setsid', 'exec', 'time', 'command', 'stdbuf'])
const LISTE_ENV = new Set(['gci', 'dir', 'ls', 'get-childitem', 'get-item'])

type Contexte = { rep: string; motifs: RegExp[]; powershell: boolean }

function estSecret(mot: string, motifs: RegExp[]): boolean {
  const m = mot.replace(/^['"]+|['"]+$/g, '').replace(/\\/g, '/') // chemins Windows
  if (EXEMPLES.test(m)) return false
  return SECRETS.some(r => r.test(m)) || motifs.some(r => r.test(m))
}

/** Noms des secrets reconnus dans un contenu — jamais leur valeur. */
export function trouverSecrets(texte: string): string[] {
  const noms = JETONS.filter(([, rx]) => rx.test(texte)).map(([nom]) => nom)
  for (const m of texte.matchAll(new RegExp(URL_IDENTIFIANTS, 'g'))) {
    if (!FACTICE.test(m[1] ?? '')) { noms.push('identifiants dans une URL'); break }
  }
  for (const [motif, drapeaux] of AFFECTATIONS) {
    for (const m of texte.matchAll(new RegExp(motif, drapeaux))) {
      const cle = m[1] ?? '', val = m[2] ?? ''
      if (CLE_ANODINE.test(cle) || FACTICE.test(val)) continue
      if (!(/[A-Za-z]/.test(val) && /[0-9]/.test(val))) continue
      noms.push(`valeur en dur pour « ${cle.slice(0, 40)} »`)
      return noms
    }
  }
  return noms
}

function nomCommande(t: string): string {
  return (t.split('/').pop() ?? '').replace(/\.exe$/i, '')
}

function premierMot(toks: string[], powershell = false): [number | undefined, string] {
  let i = 0
  while (i < toks.length) {
    const t = toks[i] ?? ''
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { i += 1; continue }
    if (ENVELOPPES.has(t)) {
      i += 1
      if (t === 'timeout' && i < toks.length && /^[0-9.]+[smhd]?$/.test(toks[i] ?? '')) i += 1
      continue
    }
    const nom = nomCommande(t)
    return [i, powershell ? nom.toLowerCase() : nom]
  }
  return [undefined, '']
}

/** Découpe hors guillemets sur les séparateurs donnés. */
function decouper(cmd: string, seps: string[]): string[] {
  const out: string[] = []
  let cur = '', q: string | undefined, i = 0
  while (i < cmd.length) {
    const c = cmd[i] ?? ''
    if (q !== undefined) {
      cur += c
      if (c === q) q = undefined
      else if (c === '\\' && q === '"' && i + 1 < cmd.length) { cur += cmd[i + 1]; i += 1 }
    } else if (c === "'" || c === '"') {
      q = c; cur += c
    } else {
      const hit = seps.find(s => cmd.startsWith(s, i))
      if (hit !== undefined) { out.push(cur); cur = ''; i += hit.length; continue }
      cur += c
    }
    i += 1
  }
  out.push(cur)
  return out.map(s => s.trim()).filter(s => s !== '')
}

/** Contenu des $( … ) (un niveau). */
function substitutions(cmd: string): string[] {
  const res: string[] = []
  let i = 0
  for (;;) {
    const j = cmd.indexOf('$(', i)
    if (j < 0) return res
    let prof = 1, k = j + 2
    while (k < cmd.length && prof > 0) {
      if (cmd[k] === '(') prof += 1
      else if (cmd[k] === ')') prof -= 1
      k += 1
    }
    res.push(cmd.slice(j + 2, k - 1)); i = k
  }
}

/** Découpage en mots à la manière d'un shell POSIX ; lève une erreur sur un guillemet non fermé. */
function motsShell(s: string): string[] {
  const out: string[] = []
  let cur = '', dans = false, q: string | undefined, i = 0
  while (i < s.length) {
    const c = s[i] ?? ''
    if (q === "'") {
      if (c === "'") q = undefined
      else cur += c
    } else if (q === '"') {
      if (c === '"') q = undefined
      else if (c === '\\' && i + 1 < s.length && '"\\$`\n'.includes(s[i + 1] ?? '')) { cur += s[i + 1]; i += 1 }
      else cur += c
    } else if (c === "'" || c === '"') {
      q = c; dans = true
    } else if (c === '\\' && i + 1 < s.length) {
      cur += s[i + 1]; dans = true; i += 1
    } else if (/\s/.test(c)) {
      if (dans || cur !== '') { out.push(cur); cur = ''; dans = false }
    } else {
      cur += c
    }
    i += 1
  }
  if (q !== undefined) throw new Error('guillemet non fermé')
  if (dans || cur !== '') out.push(cur)
  return out
}

function joindre(rep: string, p: string, maison: string | undefined): string {
  let abs = p
  if (p === '~' || p.startsWith('~/')) abs = (maison ?? '') + p.slice(1)
  else if (!(p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p))) abs = `${rep}/${p}`
  const parts: string[] = []
  for (const seg of abs.replace(/\\/g, '/').split('/')) {
    if (seg === '..') { if (parts.length > 1) parts.pop() }
    else if (seg !== '.' && (seg !== '' || parts.length === 0)) parts.push(seg)
  }
  return parts.join('/') || '/'
}

async function git($: EngineInterface, rep: string, args: string[]): Promise<string> {
  try {
    const r = await $.process.run(['git', '-C', rep, ...args], { timeoutMs: 8000 })
    return r.exitCode === 0 ? r.stdout : ''
  } catch {
    return ''
  }
}

/** Fichiers qu'un « git add » ferait entrer : nom secret, ou contenu reconnu. */
async function examinerFichiers($: EngineInterface, ctx: Contexte, rep: string, chemins: string[]): Promise<string[]> {
  const res: string[] = []
  for (const c of chemins.slice(0, 2000)) {
    if (estSecret(c, ctx.motifs)) { res.push(`${c} (fichier secret)`); continue }
    let texte: string
    try {
      texte = String(await $.fs.read(`${rep}/${c}`))
    } catch {
      continue
    }
    if (texte.includes('\0')) continue
    const noms = trouverSecrets(texte.slice(0, 1000000))
    if (noms.length > 0) res.push(`${c} (${noms.join(', ')})`)
  }
  return res
}

/** Lignes ajoutées d'un diff, regroupées par fichier. */
function examinerDiff(diff: string): string[] {
  const ajouts = new Map<string, string[]>()
  let fichier: string | undefined
  for (const ligne of diff.split('\n')) {
    if (ligne.startsWith('+++ ')) fichier = ligne.slice(4, 6) === 'b/' ? ligne.slice(6) : undefined
    else if (ligne.startsWith('+') && fichier !== undefined) {
      const l = ajouts.get(fichier) ?? []
      l.push(ligne.slice(1)); ajouts.set(fichier, l)
    }
  }
  const res: string[] = []
  for (const [f, lignes] of ajouts) {
    const noms = trouverSecrets(lignes.join('\n'))
    if (noms.length > 0) res.push(`${f} (${noms.join(', ')})`)
  }
  return res
}

/** Renvoie une raison de refus pour une commande git, ou undefined. */
async function controleGit($: EngineInterface, ctx: Contexte, args: string[], visible: boolean, maison: string | undefined): Promise<string | undefined> {
  let rep = ctx.rep, i = 0
  while (i < args.length && (args[i] ?? '').startsWith('-')) {
    if (args[i] === '-C' && i + 1 < args.length) { rep = joindre(rep, args[i + 1] ?? '', maison); i += 2; continue }
    i += args[i] === '-c' ? 2 : 1
  }
  if (i >= args.length) return undefined
  const sub = args[i] ?? '', reste = args.slice(i + 1)
  if (['show', 'diff', 'blame', 'cat-file', 'grep'].includes(sub) || (sub === 'log' && reste.some(a => ['-p', '-u', '--patch'].includes(a)))) {
    const vus = [...new Set(reste.flatMap(a => a.split(':')).filter(p => p !== '' && estSecret(p, ctx.motifs)))].sort()
    return visible && vus.length > 0 ? `« git ${sub} » afficherait le contenu de ${vus.join(', ')}` : undefined
  }
  let trouvailles: string[]
  if (sub === 'add') {
    const sansDialogue = reste.filter(a => !['-p', '-i', '-e', '--patch', '--interactive', '--edit'].includes(a))
    const sortie = await git($, rep, ['add', '--dry-run', ...sansDialogue])
    const chemins = [...sortie.matchAll(/^add '(.*)'$/gm)].map(m => m[1] ?? '')
    trouvailles = await examinerFichiers($, ctx, rep, chemins)
  } else if (sub === 'commit') {
    const tout = reste.some(a => a === '--all' || /^-[A-Za-z]*a[A-Za-z]*$/.test(a))
    let noms = (await git($, rep, ['diff', '--cached', '--name-only', '--diff-filter=ACMR'])).split('\n')
    let diff = await git($, rep, ['diff', '--cached', '-U0', '--no-color', '--diff-filter=ACMR'])
    if (tout) {
      noms = noms.concat((await git($, rep, ['diff', '--name-only', '--diff-filter=ACMR'])).split('\n'))
      diff += '\n' + (await git($, rep, ['diff', '-U0', '--no-color', '--diff-filter=ACMR']))
    }
    const secrets = [...new Set(noms.filter(n => n !== '' && estSecret(n, ctx.motifs)))].sort()
    trouvailles = secrets.map(n => `${n} (fichier secret)`)
      .concat(examinerDiff(diff).filter(t => !secrets.includes(t.split(' (')[0] ?? '')))
  } else {
    return undefined
  }
  if (trouvailles.length === 0) return undefined
  const plus = trouvailles.length > 8 ? ` ; … (${trouvailles.length - 8} autres)` : ''
  return `« git ${sub} » ferait entrer des secrets dans le dépôt : ${trouvailles.slice(0, 8).join(' ; ')}${plus}. ${CONSEIL_GIT}`
}

function controleTerraform(mot: string, args: string[]): string | undefined {
  const pos = args.filter(a => !a.startsWith('-') && a !== 'run-all' && a !== 'run')
  const opts = new Set(args.filter(a => a.startsWith('-')).map(a => a.replace(/^-+/, '').split('=')[0]))
  if (pos.length === 0) return undefined
  const sub = pos[0], reste = pos.slice(1)
  if (sub === 'show') return `« ${mot} show » affiche l'état ou le plan en entier, valeurs sensibles comprises`
  if (sub === 'console') return `« ${mot} console » donne accès à toutes les valeurs de l'état`
  if (sub === 'state' && (reste[0] === 'pull' || reste[0] === 'show')) return `« ${mot} state ${reste[0]} » affiche l'état, valeurs sensibles comprises`
  if (sub === 'output' && (reste.length > 0 || opts.has('json') || opts.has('raw'))) {
    return `« ${mot} output » avec un nom, -json ou -raw affiche les sorties sensibles en clair (sans argument, elles restent masquées)`
  }
  return undefined
}

/** Commandes qui affichent des variables d'environnement ou impriment un secret. */
function controleEnv(mot: string, args: string[], ligne: string): string | undefined {
  if (['echo', 'printf', 'write-output', 'write-host'].includes(mot)) {
    const vus = [...new Set(args.flatMap(a => [...a.matchAll(new RegExp(VAR_SECRETE, 'gi'))].map(m => m[0])))].sort()
    if (vus.length > 0) return `« ${mot} » afficherait la valeur de ${vus.join(', ')}`
  }
  if (/^\$env:/i.test(mot) && NOM_SECRET.test(mot)) return `cette commande afficherait la valeur de ${mot}`
  if (mot === 'printenv') {
    const noms = args.filter(a => !a.startsWith('-'))
    if (noms.length === 0 || noms.some(a => NOM_SECRET.test(a))) {
      return '« printenv » afficherait des variables secrètes (demande une variable précise et anodine : printenv NOM)'
    }
  }
  if ((mot === 'set' && args.length === 0) || (mot === 'export' && (args.length === 0 || (args.length === 1 && args[0] === '-p'))) ||
      (mot === 'declare' && args.length > 0 && args.every(a => ['-p', '-x', '-px', '-xp'].includes(a))) ||
      (LISTE_ENV.has(mot) && args.some(a => /^env:/i.test(a)))) {
    return `« ${mot} » afficherait toutes les variables d'environnement, jetons compris`
  }
  if (mot === 'docker' && /^docker inspect\b/.test(ligne)) {
    if (!/ (--format|-f)[ =]/.test(ligne) || /Env|Config\b/.test(ligne)) {
      return "« docker inspect » sans --format ciblé affiche les variables d'environnement du conteneur"
    }
  }
  for (const [rx, raison] of IMPRIME_SECRET) if (rx.test(ligne)) return raison
  return undefined
}

/** Renvoie une raison de refus, ou undefined. */
async function analyser($: EngineInterface, ctx: Contexte, cmd: string, maison: string | undefined, affiche = true, profondeur = 0, local = true): Promise<string | undefined> {
  if (profondeur > 4) return undefined
  // Les $( … ) : leur sortie va à la commande englobante.
  for (const sub of substitutions(cmd)) {
    const r = await analyser($, ctx, sub, maison, false, profondeur + 1, local)
    if (r !== undefined) return r
  }
  const sansSub = cmd.replace(/\$\((?:[^()]|\([^()]*\))*\)/g, 'SUBST')
  for (const seg of decouper(sansSub, ['&&', '||', ';', '\n'])) {
    const etapes = decouper(seg, ['|'])
    for (let n = 0; n < etapes.length; n += 1) {
      const etape = etapes[n] ?? ''
      let toks: string[]
      try {
        toks = motsShell(etape)
      } catch {
        toks = etape.split(/\s+/).filter(t => t !== '')
      }
      if (toks.some(t => TF_LOG.test(t))) return 'TF_LOG=TRACE/DEBUG écrit les échanges avec les fournisseurs, identifiants compris'
      const [i, mot] = premierMot(toks, ctx.powershell)
      const redirige = /(^|[^<0-9&])>{1,2}\s*[^&\s]/.test(etape) && !/\btee\b/.test(etape)
      const suite = etapes.slice(n + 1)
      const versPuits = suite.length > 0 && PUITS.has(premierMot((suite[0] ?? '').split(/\s+/).filter(t => t !== ''), ctx.powershell)[1])
      const visible = affiche && !redirige && !versPuits
      if (i === undefined) {
        if (visible && toks.includes('env')) return "« env » afficherait toutes les variables d'environnement, jetons compris"
        continue
      }
      const args = toks.slice(i + 1)
      if (mot === 'cd' && args.length > 0 && local) ctx.rep = joindre(ctx.rep, args[0] ?? '', maison)
      // Commandes distantes ou enveloppées : on analyse la chaîne qu'elles exécutent.
      if (mot === 'ssh') {
        const distante = args.filter(a => a.includes(' ') || a.includes(';') || a.includes('|'))
        for (const d of distante.slice(-1)) {
          const r = await analyser($, ctx, d, maison, affiche && n === etapes.length - 1, profondeur + 1, false)
          if (r !== undefined) return r
        }
      }
      // Toute chaîne passée par « -c » (sh -c, bash -c, docker run … sh -c, chroot … sh -c…) est analysée.
      if (mot !== 'git') {
        for (let k = 0; k + 1 < args.length; k += 1) {
          if (args[k] !== '-c') continue
          const r = await analyser($, ctx, args[k + 1] ?? '', maison, affiche && n === etapes.length - 1, profondeur + 1,
            local && ['sh', 'bash', 'zsh', 'dash'].includes(mot))
          if (r !== undefined) return r
        }
      }
      if (mot === 'git' && local) {
        const r = await controleGit($, ctx, args, visible, maison)
        if (r !== undefined) return r
      }
      if (TERRAFORM.has(mot) && affiche && !versPuits) {
        const r = controleTerraform(mot, args)
        if (r !== undefined) return r
      }
      if (visible) {
        const r = controleEnv(mot, args, [mot, ...args].join(' '))
        if (r !== undefined) return r
      }
      if (!AFFICHAGE.has(mot)) continue
      // Fichiers secrets lus par cette étape (hors redirection de sortie « > f »)
      const lus: string[] = []
      let prec = ''
      for (let a of args) {
        if (['>', '>>', '2>', '&>'].includes(prec) || a.startsWith('>')) { prec = a; continue }
        if (a.startsWith('<') && a.length > 1) a = a.slice(1)
        if (estSecret(a, ctx.motifs)) lus.push(a)
        prec = a
      }
      if (lus.length === 0) continue
      if (mot === 'sed' && args.some(a => a.startsWith('-i')) && !args.includes('-n')) continue // édition en place sans affichage
      if (!visible) continue
      return `« ${mot} » afficherait le contenu de ${[...new Set(lus)].sort().join(', ')}`
    }
  }
  return undefined
}

function refus(raison: string): string {
  return 'garde-secrets : ' + raison + '. Un secret ne doit être ni lu, ni affiché, ' +
    'ni commité. Restent permis : copier le fichier, le supprimer, lire ses métadonnées (stat, ls), ' +
    "comparer son empreinte (sha256sum). Ne cherche pas un autre moyen d'y arriver : dis à l'utilisateur " +
    "ce qui a été refusé. Si le blocage est une erreur, c'est à lui de faire l'opération ou de " +
    'désactiver le plugin garde-secrets.'
}

/** Le dossier personnel, ou undefined ; une variable illisible ne doit pas désarmer le garde. */
async function dossierPerso($: EngineInterface): Promise<string | undefined> {
  try {
    return (await $.env.get('HOME')) || (await $.env.get('USERPROFILE')) || undefined
  } catch {
    return undefined
  }
}

/** Motifs personnels : une expression régulière par ligne ; ils s'ajoutent à la liste, sans rien en retirer. */
async function motifsPerso($: EngineInterface, maison: string | undefined): Promise<RegExp[]> {
  let texte: string
  try {
    const chemin = (await $.env.get('GARDE_SECRETS_MOTIFS')) || (maison === undefined ? undefined : `${maison}/.config/garde-secrets/motifs.txt`)
    if (chemin === undefined) return []
    texte = String(await $.fs.read(chemin))
  } catch {
    return []
  }
  const res: RegExp[] = []
  for (const brut of texte.split('\n')) {
    const ligne = brut.trim()
    if (ligne === '' || ligne.startsWith('#')) continue
    try {
      res.push(new RegExp(ligne))
    } catch {
      // motif invalide : ignoré
    }
  }
  return res
}

const txt = (v: unknown): string => (typeof v === 'string' ? v : '')

/** La raison de refuser cet appel d'outil, ou undefined. */
async function decider($: EngineInterface, e: Record<string, unknown>): Promise<string | undefined> {
  const outil = txt(e.tool)
  const lecture = ['Read', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(outil)
  const shell = outil === 'Bash' || outil === 'PowerShell'
  if (!lecture && !shell && outil !== 'Grep') return undefined
  const chemins = lecture ? [txt(e.file_path) || txt(e.notebook_path)] : outil === 'Grep' ? [txt(e.path), txt(e.glob)] : []
  const raisonPour = (p: string) => (lecture ? `lecture de ${p} par ${outil}` : `recherche dans ${p}`)
  // La liste de base d'abord, sans rien demander au moteur : ce refus-là ne dépend de rien.
  for (const p of chemins) if (p !== '' && estSecret(p, [])) return raisonPour(p)
  const maison = await dossierPerso($)
  const motifs = await motifsPerso($, maison)
  for (const p of chemins) if (p !== '' && estSecret(p, motifs)) return raisonPour(p)
  if (!shell) return undefined
  const powershell = outil === 'PowerShell'
  const cmd = powershell ? txt(e.command).replace(/\\/g, '/') : txt(e.command)
  try {
    let rep = '.'
    try {
      rep = await $.session.cwd()
    } catch {
      // dossier inconnu : les contrôles git se feront depuis le dossier courant
    }
    return await analyser($, { rep, motifs, powershell }, cmd, maison)
  } catch {
    // En cas de doute (analyse impossible) : refus si un verbe d'affichage côtoie un chemin secret.
    const mots = cmd.match(/[^\s'";|&()<>]+/g) ?? []
    return mots.some(m => AFFICHAGE.has(nomCommande(m))) && mots.some(m => estSecret(m, motifs))
      ? 'commande non analysable mêlant affichage et fichier secret'
      : undefined
  }
}

export const register: Register = on => {
  on('tool.call', async ($, e, next) => {
    const raison = await decider($, e as unknown as Record<string, unknown>)
    return raison === undefined ? next(e) : { deny: refus(raison) }
  })
}
