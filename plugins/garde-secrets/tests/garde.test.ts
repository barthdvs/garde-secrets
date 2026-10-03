// Banc d'essai du module : claude plugin test <dossier du plugin>
// Les cas communs sont les mêmes que ceux du secours Python (tests/cas.py).
// Les faux secrets sont assemblés par morceaux pour que ce fichier n'en contienne aucun tel quel.
import { expect, test } from 'claude-code/testing'
import type { EngineInterface, On, SessionAppendInput } from 'claude-code'
import { CAS } from './cas-communs'
import { masquer, masquerLigne, REPERE } from '../hooks/garde'

type Entree = string | Record<string, unknown>
type Monde = { motifs?: string; fichiers?: Record<string, string>; git?: (argv: readonly string[]) => string }

const F_GITHUB = 'gh' + 'p_' + 'a1B2'.repeat(9)
const F_AWS = 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP'
const F_CLE = '-----BEGIN ' + 'RSA PRIVATE KEY-----\nMIIfaux\n'
const F_MDP = 'pass' + 'word = "Xk29fjdk20dkfj3"\n'
const F_YAML = 'api_' + 'key: 9f8e7d6c5b4a39281706f5e4\n' // gitleaks:allow (faux secret du banc d'essai)
const F_URL = 'DATABASE_URL=postgres://appli:' + 's3cretMdp42' + '@db.example.com/base\n'

// Faux secrets des cas de masquage : « {F:NOM} » dans cas-communs.ts (mêmes valeurs dans tests/cas.py)
const F: Record<string, string> = {
  HEX32: '0123456789abcdef'.repeat(2),
  MDP: 'Xk29' + 'fjdk20dkfj3',
  B64: 'dXNlcjpz' + 'M2NyZXQ0Mg==',
  GITHUB: F_GITHUB,
  AWS: F_AWS,
  GITLAB: 'gl' + 'pat-' + 'a1B2c3D4e5F6g7H8i9J0',
  SLACK: 'xo' + 'xb-' + '1234567890-abcdefghij',
  SLACK_WEBHOOK: 'T0ABC' + 'DEF12/B0ABC' + 'DEF34/a1b2c3d4e5f6g7h8',
  ANTHROPIC: 'sk-' + 'ant-' + 'a1b2c3d4'.repeat(4),
  OPENAI: 'sk-' + 'proj-' + 'A1b2C3d4'.repeat(5),
  GOOGLE: 'AI' + 'za' + 'B1c2D3e4F5'.repeat(3) + 'g6h7i',
  STRIPE: 'sk' + '_live_' + 'a1B2c3D4'.repeat(3),
  VAULT: 'hv' + 's.' + 'A1b2C3d4'.repeat(4),
  NPM: 'np' + 'm_' + 'a1B2c3D4e5F6'.repeat(3),
  SCW: 'SC' + 'W' + 'ABCDEFGHJ0123456K',
  JWT: 'ey' + 'JhbGciOiJIUzI1NiJ9.' + 'ey' + 'JzdWIiOiIxMjM0NTYifQ.' + 'c2lnbmF0dXJlZmF1c3Nl',
  CLE: '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----\nMIIfaux\nAAAA\n-----END ' + 'OPENSSH PRIVATE KEY-----',
  CLE_TRONQUEE: '-----BEGIN ' + 'PRIVATE KEY-----\nMIIfaux\nAAAA',
}
const remplir = (s: string) => s.replace(/\{F:([A-Z0-9_]+)\}/g, (m: string, nom: string) => F[nom] ?? m)
const valeurs = (s: string) => Object.values(F).filter(v => s.includes(v))

/** Ce que le moteur répondrait sous le plugin : outil exécuté, dossier, fichiers et git simulés. */
function monde(on: On, m: Monde = {}): void {
  on('tool.call', () => ({ result: 'exécuté' }))
  on('session.cwd', () => ({ value: '/depot' }))
  on('env.get', (_$, e) => ({ value: e.name === 'GARDE_SECRETS_MOTIFS' ? '/motifs.txt' : '' }))
  on('fs.read', (_$, e) => {
    const texte = e.path === '/motifs.txt' ? m.motifs : m.fichiers?.[e.path]
    return texte === undefined ? { deny: 'absent' } : { value: texte }
  })
  on('process.run', (_$, e) => ({ value: { exitCode: 0, stdout: m.git?.(e.argv) ?? '', stderr: '' } }))
}

async function decision($: EngineInterface, outil: string, entree: Entree): Promise<{ refuse: boolean; raison: string }> {
  const appel = typeof entree === 'string' ? { tool: outil, command: entree } : { tool: outil, ...entree }
  const r = (await $.tool.call(appel as never)) as { deny?: string; isError?: boolean; text?: string }
  return { refuse: r.deny !== undefined || r.isError === true, raison: r.deny ?? r.text ?? '' }
}

test('refuse ce qui ferait sortir un secret', { timeoutMs: 60000 }, async ($, on) => {
  monde(on)
  const rates: string[] = []
  for (const [outil, entree] of CAS.refus as [string, Entree][]) {
    if (!(await decision($, outil, entree)).refuse) rates.push(`${outil} ${JSON.stringify(entree)}`)
  }
  expect(rates).toEqual([])
})

test('laisse passer le travail normal', { timeoutMs: 60000 }, async ($, on) => {
  monde(on)
  const rates: string[] = []
  for (const [outil, entree] of CAS.passe as [string, Entree][]) {
    if ((await decision($, outil, entree)).refuse) rates.push(`${outil} ${JSON.stringify(entree)}`)
  }
  expect(rates).toEqual([])
})

test('les motifs personnels ajoutent des refus sans rien retirer', async ($, on) => {
  monde(on, { motifs: '# essai\nclients\\.csv$\n(motif invalide\n' })
  for (const [outil, entree] of CAS.refusPerso as [string, Entree][]) {
    expect((await decision($, outil, entree)).refuse).toBe(true)
  }
})

test('le message de refus est signé et explique quoi faire', async ($, on) => {
  monde(on)
  const { raison } = await decision($, 'Read', { file_path: '/srv/app/.env' })
  expect(raison).toMatch(/^garde-secrets : lecture de \/srv\/app\/\.env par Read/)
})

const FAUX: [string, string, string | undefined][] = [
  ['config.py', `JETON = '${F_GITHUB}'\n`, F_GITHUB],
  ['deploy.sh', `export CLE=${F_AWS}\n`, F_AWS],
  ['cle.txt', F_CLE, undefined],
  ['settings.py', F_MDP, 'Xk29fjdk20dkfj3'],
  ['values.yaml', F_YAML, '9f8e7d6c5b4a39281706f5e4'],
  ['compose.yaml', F_URL, 's3cretMdp42'],
]
const PROPRE = 'variable "db_password" {\n  sensitive = true\n}\nresource "x" "y" {\n  password = var.db_password\n' +
  '  token_url = "https://auth.example.com/oauth2/token"\n  api_key = "${var.api_key}"\n}\n'

test('git add refuse un contenu secret, jamais en montrant la valeur', async ($, on) => {
  const fichiers: Record<string, string> = { '/depot/main.tf': PROPRE }
  let liste = ['main.tf']
  monde(on, { fichiers, git: argv => (argv.includes('--dry-run') ? liste.map(f => `add '${f}'`).join('\n') + '\n' : '') })
  expect((await decision($, 'Bash', 'git add .')).refuse).toBe(false)
  for (const [nom, contenu, valeur] of FAUX) {
    fichiers[`/depot/${nom}`] = contenu
    liste = ['main.tf', nom]
    const d = await decision($, 'Bash', 'git add .')
    expect(d.refuse).toBe(true)
    expect(d.raison).toContain(nom)
    if (valeur !== undefined) expect(d.raison.includes(valeur)).toBe(false)
  }
  liste = ['.env']
  expect((await decision($, 'Bash', 'git add -f .env')).refuse).toBe(true)
  liste = ['infra/terraform.tfstate']
  expect((await decision($, 'Bash', 'git add infra')).refuse).toBe(true)
})

test('git commit refuse ce qui est indexé, et les modifications suivies avec -a', async ($, on) => {
  let indexe = '', nonIndexe = '', noms = ''
  const diff = (f: string, t: string) => `diff --git a/${f} b/${f}\n--- a/${f}\n+++ b/${f}\n@@ -0,0 +1 @@\n` + t.trimEnd().split('\n').map(l => '+' + l).join('\n') + '\n'
  monde(on, {
    git: argv => {
      if (!argv.includes('diff')) return ''
      const cache = argv.includes('--cached')
      if (argv.includes('--name-only')) return cache ? noms : ''
      return cache ? indexe : nonIndexe
    },
  })
  expect((await decision($, 'Bash', "git commit -m 'rien de neuf'")).refuse).toBe(false)
  for (const [nom, contenu, valeur] of FAUX) {
    indexe = diff(nom, contenu); noms = nom + '\n'
    for (const cmd of ['git commit -m x', 'git -C /depot commit -m x', 'cd sous && git commit -m x']) {
      const d = await decision($, 'Bash', cmd)
      expect(d.refuse).toBe(true)
      if (valeur !== undefined) expect(d.raison.includes(valeur)).toBe(false)
    }
  }
  indexe = diff('main.tf', PROPRE); noms = 'main.tf\n'
  expect((await decision($, 'Bash', 'git commit -m x')).refuse).toBe(false)
  indexe = ''; noms = '.env\n'
  expect((await decision($, 'Bash', 'git commit -m x')).refuse).toBe(true)
  noms = ''; nonIndexe = diff('README.md', `jeton : ${F_GITHUB}\n`)
  expect((await decision($, 'Bash', 'git commit -m x')).refuse).toBe(false)
  expect((await decision($, 'Bash', 'git commit -am x')).refuse).toBe(true)
  expect((await decision($, 'Bash', 'git commit --all -m x')).refuse).toBe(true)
})

test('masque les secrets reconnus dans une sortie, jamais leur nom', async () => {
  const rates: string[] = []
  for (const [entree, attendu] of CAS.masquage as [string, string][]) {
    const m = masquer(remplir(entree))
    if (m.texte !== remplir(attendu) || m.nombre === 0 || masquer(m.texte).nombre !== 0) rates.push(`${entree} → ${m.texte}`)
    if (m.types.join(' ').includes(REPERE) || valeurs(m.types.join(' ')).length > 0) rates.push(`types : ${entree}`)
  }
  for (const entree of CAS.intact as string[]) {
    const m = masquer(remplir(entree))
    if (m.texte !== remplir(entree) || m.nombre !== 0) rates.push(`masqué à tort : ${entree} → ${m.texte}`)
  }
  expect(rates).toEqual([])
})

const CAS_REEL = 'Erreur GET http://hote:9696/1/api?t=movie&apikey=' + F.HEX32 + '&offset=0'

test('la sortie de Bash est masquée avant que le modèle la lise, avec une note', async ($, on) => {
  let sortie = ''
  on('tool.call', () => ({ result: { stdout: sortie, stderr: 'avertissement : ' + F.GITHUB, interrupted: false } }))
  on('session.cwd', () => ({ value: '/depot' }))
  on('env.get', () => ({ value: '' }))
  on('fs.read', () => ({ deny: 'absent' }))
  sortie = `{"message":"${CAS_REEL}"}`
  const r = (await $.tool.call({ tool: 'Bash', command: 'curl -s http://hote:9696/1/api' } as never)) as
    { result?: { stdout: string; stderr: string; interrupted: boolean }; context?: string[] }
  expect(r.result?.stdout).toBe(`{"message":"Erreur GET http://hote:9696/1/api?t=movie&apikey=${REPERE}&offset=0"}`)
  expect(r.result?.stderr).toBe('avertissement : ' + REPERE)
  expect(r.result?.interrupted).toBe(false)
  const note = (r.context ?? []).join('\n')
  expect(note).toContain('garde-secrets : 2 valeurs secrètes masquées dans cette sortie')
  expect(note).toContain('jeton GitHub')
  expect(valeurs(JSON.stringify(r))).toEqual([])
  // rien à masquer : le résultat est rendu tel quel, sans note
  sortie = 'total 0\nsecrets.txt\n'
  const r2 = (await $.tool.call({ tool: 'PowerShell', command: 'dir' } as never)) as { result?: { stdout: string }; context?: string[] }
  expect(r2.result?.stdout).toBe(sortie)
})

test("la sortie d'un autre outil que le shell n'est pas touchée", async ($, on) => {
  on('tool.call', () => ({ result: { contenu: CAS_REEL } }))
  on('env.get', () => ({ value: '' }))
  on('fs.read', () => ({ deny: 'absent' }))
  const r = (await $.tool.call({ tool: 'WebFetch', url: 'https://example.com', prompt: 'x' } as never)) as { result?: { contenu: string } }
  expect(r.result?.contenu).toBe(CAS_REEL)
})

test('une commande en échec est masquée dans la ligne que garde la conversation', async () => {
  const ligne = (contenu: unknown, door = 'tool-result', tool = 'Bash') => ({
    door, uuid: 'u', origin: { kind: 'tool', tool },
    message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', is_error: true, content: contenu }] },
  }) as unknown as SessionAppendInput
  const m = masquerLigne(ligne('Exit code 22\n' + CAS_REEL))
  const bloc = (m?.content[0] ?? {}) as { content?: string; is_error?: boolean; tool_use_id?: string }
  expect(bloc.content).toContain(`&apikey=${REPERE}&offset=0`)
  expect(bloc.content).toContain('garde-secrets : 1 valeur secrète masquée dans cette sortie')
  expect(bloc.is_error).toBe(true)
  expect(bloc.tool_use_id).toBe('t1')
  expect(valeurs(JSON.stringify(m))).toEqual([])
  const m2 = masquerLigne(ligne([{ type: 'text', text: CAS_REEL }], 'tool-result', 'PowerShell'))
  expect(valeurs(JSON.stringify(m2))).toEqual([])
  expect(JSON.stringify(m2)).toContain('garde-secrets : 1 valeur')
  // déjà masqué, autre outil, autre sorte de ligne : rien à faire
  expect(masquerLigne(ligne(`apikey=${REPERE}`))).toBe(undefined)
  expect(masquerLigne(ligne(CAS_REEL, 'tool-result', 'Read'))).toBe(undefined)
  expect(masquerLigne(ligne(CAS_REEL, 'prompt'))).toBe(undefined)
})
