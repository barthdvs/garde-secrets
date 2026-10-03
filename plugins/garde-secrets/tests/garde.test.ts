// Banc d'essai du module : claude plugin test <dossier du plugin>
// Les cas communs sont les mêmes que ceux du secours Python (tests/cas.py).
// Les faux secrets sont assemblés par morceaux pour que ce fichier n'en contienne aucun tel quel.
import { expect, test } from 'claude-code/testing'
import type { EngineInterface, On } from 'claude-code'
import { CAS } from './cas-communs'

type Entree = string | Record<string, unknown>
type Monde = { motifs?: string; fichiers?: Record<string, string>; git?: (argv: readonly string[]) => string }

const F_GITHUB = 'gh' + 'p_' + 'a1B2'.repeat(9)
const F_AWS = 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP'
const F_CLE = '-----BEGIN ' + 'RSA PRIVATE KEY-----\nMIIfaux\n'
const F_MDP = 'pass' + 'word = "Xk29fjdk20dkfj3"\n'
const F_YAML = 'api_' + 'key: 9f8e7d6c5b4a39281706f5e4\n' // gitleaks:allow (faux secret du banc d'essai)
const F_URL = 'DATABASE_URL=postgres://appli:' + 's3cretMdp42' + '@db.example.com/base\n'

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
