// Cas communs aux deux moteurs (module TypeScript et secours Python).
// Ce qui suit « export const CAS » est du JSON strict : tests/cas.py le relit tel quel.
export const CAS = {
 "refus": [
  [
   "Bash",
   "openssl pkey -in tls/ca.key -pubout"
  ],
  [
   "Bash",
   "file /etc/app/secrets/maitre.key"
  ],
  [
   "Bash",
   "cat /srv/app/.env"
  ],
  [
   "Bash",
   "ssh root@serveur 'cat /etc/stacks/proxy/.env'"
  ],
  [
   "Bash",
   "ssh -p 2222 user@nas 'D=/x/docker; $D run --rm -v /c:/c alpine sh -c \"cat /c/vault/role_id\"'"
  ],
  [
   "Bash",
   "cat /home/user/.config/forge/token"
  ],
  [
   "Bash",
   "tail -n 3 /home/user/.config/supervision/admin-password"
  ],
  [
   "Bash",
   "sed -n 1,20p /srv/sso/config/secrets/jwt.txt"
  ],
  [
   "Bash",
   "cat /srv/sso/config/private.pem | head"
  ],
  [
   "Bash",
   "cat ~/.ssh/id_ed25519"
  ],
  [
   "Bash",
   "head -5 /home/user/.aws/credentials"
  ],
  [
   "Bash",
   "cat ~/.netrc"
  ],
  [
   "Bash",
   "cat /proc/self/environ"
  ],
  [
   "Read",
   {
    "file_path": "/etc/app/secrets/maitre.key"
   }
  ],
  [
   "Read",
   {
    "file_path": "/srv/app/.env"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/.ssh/id_rsa"
   }
  ],
  [
   "Read",
   {
    "file_path": "C:\\Users\\user\\projet\\.env"
   }
  ],
  [
   "Read",
   {
    "file_path": "C:\\Users\\user\\.ssh\\id_ed25519"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/coffre.kdbx"
   }
  ],
  [
   "Grep",
   {
    "pattern": "x",
    "path": "/home/user/.config/pki/ca.key"
   }
  ],
  [
   "Edit",
   {
    "file_path": "/etc/sso/private.pem",
    "old_string": "a",
    "new_string": "b"
   }
  ],
  [
   "Bash",
   "terraform show"
  ],
  [
   "Bash",
   "terraform show -json tfplan | jq '.resource_changes[].address'"
  ],
  [
   "Bash",
   "terraform show -json tfplan > plan.json"
  ],
  [
   "Bash",
   "terraform state pull"
  ],
  [
   "Bash",
   "terraform state show aws_db_instance.base"
  ],
  [
   "Bash",
   "terraform output -json"
  ],
  [
   "Bash",
   "terraform output db_password"
  ],
  [
   "Bash",
   "tofu output -raw jeton"
  ],
  [
   "Bash",
   "terraform console"
  ],
  [
   "Bash",
   "terragrunt run-all show"
  ],
  [
   "Bash",
   "TF_LOG=DEBUG terraform plan"
  ],
  [
   "Bash",
   "cd infra && terraform -chdir=prod state pull"
  ],
  [
   "Bash",
   "cat terraform.tfstate"
  ],
  [
   "Bash",
   "jq '.resources' .terraform/terraform.tfstate"
  ],
  [
   "Bash",
   "grep password prod.tfvars"
  ],
  [
   "Read",
   {
    "file_path": "/home/user/infra/terraform.tfstate.backup"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/infra/prod.auto.tfvars"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/infra/tfplan"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/.terraform.d/credentials.tfrc.json"
   }
  ],
  [
   "Bash",
   "echo $GITHUB_TOKEN"
  ],
  [
   "Bash",
   "echo \"clé: ${AWS_SECRET_ACCESS_KEY}\""
  ],
  [
   "Bash",
   "printenv"
  ],
  [
   "Bash",
   "printenv AWS_SECRET_ACCESS_KEY"
  ],
  [
   "Bash",
   "env"
  ],
  [
   "Bash",
   "env | grep -i aws"
  ],
  [
   "Bash",
   "export -p"
  ],
  [
   "Bash",
   "gh auth token"
  ],
  [
   "Bash",
   "aws configure get aws_secret_access_key"
  ],
  [
   "Bash",
   "gcloud auth print-access-token"
  ],
  [
   "Bash",
   "vault kv get secret/app"
  ],
  [
   "Bash",
   "kubectl get secret base -n prod -o yaml"
  ],
  [
   "Bash",
   "docker inspect appli"
  ],
  [
   "Bash",
   "docker compose config"
  ],
  [
   "Bash",
   "docker exec appli env"
  ],
  [
   "Bash",
   "git show HEAD:.env"
  ],
  [
   "Bash",
   "git diff HEAD~1 -- config/secrets/prod.yml"
  ],
  [
   "PowerShell",
   "Get-Content C:\\Users\\user\\projet\\.env"
  ],
  [
   "PowerShell",
   "type prod.tfvars"
  ],
  [
   "PowerShell",
   "gc $HOME\\.ssh\\id_ed25519"
  ],
  [
   "PowerShell",
   "Select-String -Path .\\secrets\\prod.yml -Pattern mot"
  ],
  [
   "PowerShell",
   "echo $env:GITHUB_TOKEN"
  ],
  [
   "PowerShell",
   "$env:AWS_SECRET_ACCESS_KEY"
  ],
  [
   "PowerShell",
   "Get-ChildItem Env:"
  ],
  [
   "PowerShell",
   "gci env: | Out-String"
  ],
  [
   "PowerShell",
   "terraform.exe output -json"
  ],
  [
   "PowerShell",
   "gh.exe auth token"
  ]
 ],
 "passe": [
  [
   "Bash",
   "grep -i password /etc/config/ddns"
  ],
  [
   "Bash",
   "ssh root@serveur 'cat > /etc/app/secrets/maitre.key' < /tmp/m.key"
  ],
  [
   "Bash",
   "sha256sum < /tmp/m.key | cut -c1-16"
  ],
  [
   "Bash",
   "tr -d '\\n' < /home/user/.config/forge/token | sha256sum"
  ],
  [
   "Bash",
   "printf 'header = \"Authorization: token %s\"\\n' \"$(tr -d '\\n' < /home/user/.config/forge/token)\" > /tmp/fj.h"
  ],
  [
   "Bash",
   "shred -u /etc/app/secrets/ancienne.key"
  ],
  [
   "Bash",
   "stat -c '%s %a' /etc/app/secrets/maitre.key"
  ],
  [
   "Bash",
   "ls -la /srv/app/secrets/"
  ],
  [
   "Bash",
   "cd /etc/stacks/proxy && docker run --rm --env-file .env proxy validate"
  ],
  [
   "Bash",
   "install -m 600 tls/ca.key /home/user/.config/pki/ca.key"
  ],
  [
   "Bash",
   "cat /etc/stacks/proxy/nginx.conf | grep -n portail"
  ],
  [
   "Bash",
   "git log --oneline -3"
  ],
  [
   "Bash",
   "git diff --stat"
  ],
  [
   "Bash",
   "git status --short"
  ],
  [
   "Bash",
   "sed -i 's/a/b/' /srv/app/.env"
  ],
  [
   "Bash",
   "ssh -i ~/.ssh/id_ed25519 user@serveur hostname"
  ],
  [
   "Bash",
   "cat ~/.ssh/id_ed25519.pub"
  ],
  [
   "Bash",
   "cat .env.example"
  ],
  [
   "Read",
   {
    "file_path": "/home/user/projet/.env.example"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/projet/README.md"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/projet/clients.csv"
   }
  ],
  [
   "Grep",
   {
    "pattern": "portail",
    "path": "/etc/stacks/proxy"
   }
  ],
  [
   "Bash",
   "terraform init"
  ],
  [
   "Bash",
   "terraform validate"
  ],
  [
   "Bash",
   "terraform fmt -check -recursive"
  ],
  [
   "Bash",
   "terraform plan -out=tfplan"
  ],
  [
   "Bash",
   "terraform -chdir=infra plan -var-file=prod.tfvars"
  ],
  [
   "Bash",
   "terraform apply tfplan"
  ],
  [
   "Bash",
   "terraform state list"
  ],
  [
   "Bash",
   "terraform output"
  ],
  [
   "Bash",
   "terraform providers"
  ],
  [
   "Bash",
   "terraform state pull | sha256sum"
  ],
  [
   "Read",
   {
    "file_path": "/home/user/infra/main.tf"
   }
  ],
  [
   "Read",
   {
    "file_path": "/home/user/infra/terraform.tfvars.example"
   }
  ],
  [
   "Bash",
   "printenv HOME"
  ],
  [
   "Bash",
   "echo $HOME $PWD $PATH"
  ],
  [
   "Bash",
   "env FOO=1 make build"
  ],
  [
   "Bash",
   "curl -s -H \"Authorization: Bearer $API_TOKEN\" https://api.example.com/v1/etat"
  ],
  [
   "Bash",
   "gh auth token | sha256sum"
  ],
  [
   "Bash",
   "printf '%s' \"$API_TOKEN\" > /tmp/jeton"
  ],
  [
   "Bash",
   "gh auth status"
  ],
  [
   "Bash",
   "kubectl get pods -n prod"
  ],
  [
   "Bash",
   "kubectl get secrets -n prod"
  ],
  [
   "Bash",
   "docker inspect --format '{{.State.Status}}' appli"
  ],
  [
   "Bash",
   "docker compose ps"
  ],
  [
   "PowerShell",
   "Get-Content README.md"
  ],
  [
   "PowerShell",
   "terraform.exe plan -out=tfplan"
  ],
  [
   "PowerShell",
   "Get-ChildItem C:\\Users\\user\\projet"
  ],
  [
   "PowerShell",
   "echo $env:USERPROFILE"
  ],
  [
   "PowerShell",
   "Copy-Item .env .env.bak"
  ],
  [
   "Bash",
   "type python3"
  ]
 ],
 "refusPerso": [
  [
   "Read",
   {
    "file_path": "/home/user/projet/clients.csv"
   }
  ],
  [
   "Bash",
   "head /home/user/projet/clients.csv"
  ],
  [
   "Read",
   {
    "file_path": "/srv/app/.env"
   }
  ]
 ],
 "masquage": [
  [
   "{\"message\":\"Erreur GET http://hote:9696/1/api?t=movie&apikey={F:HEX32}&offset=0\",\"status\":500}",
   "{\"message\":\"Erreur GET http://hote:9696/1/api?t=movie&apikey=<masqué par garde-secrets>&offset=0\",\"status\":500}"
  ],
  [
   "curl: (22) https://api.example.com/v1/items?token={F:HEX32} : 401",
   "curl: (22) https://api.example.com/v1/items?token=<masqué par garde-secrets> : 401"
  ],
  [
   "GET /library?X-App-Token={F:MDP} HTTP/1.1",
   "GET /library?X-App-Token=<masqué par garde-secrets> HTTP/1.1"
  ],
  [
   "https://stockage.example.com/a.png?se=2026&sig={F:B64}&sp=r",
   "https://stockage.example.com/a.png?se=2026&sig=<masqué par garde-secrets>&sp=r"
  ],
  [
   "https://example.com/connexion?user=moi&api_key={F:HEX32}#haut",
   "https://example.com/connexion?user=moi&api_key=<masqué par garde-secrets>#haut"
  ],
  [
   "DATABASE_URL=postgres://appli:{F:MDP}@db.example.com/base",
   "DATABASE_URL=postgres://appli:<masqué par garde-secrets>@db.example.com/base"
  ],
  [
   "remote: https://moi:{F:GITHUB}@git.example.com/depot.git",
   "remote: https://moi:<masqué par garde-secrets>@git.example.com/depot.git"
  ],
  [
   "> Authorization: Bearer {F:HEX32}\n> Accept: */*",
   "> Authorization: Bearer <masqué par garde-secrets>\n> Accept: */*"
  ],
  [
   "curl -H \"Authorization: Basic {F:B64}\" https://example.com",
   "curl -H \"Authorization: Basic <masqué par garde-secrets>\" https://example.com"
  ],
  [
   "curl -H 'X-Api-Key: {F:HEX32}' http://hote:8080/api/v1/items",
   "curl -H 'X-Api-Key: <masqué par garde-secrets>' http://hote:8080/api/v1/items"
  ],
  [
   "{\"headers\":{\"authorization\":\"Bearer {F:HEX32}\",\"accept\":\"*/*\"}}",
   "{\"headers\":{\"authorization\":\"Bearer <masqué par garde-secrets>\",\"accept\":\"*/*\"}}"
  ],
  [
   "{\"X-Auth-Token\": \"{F:HEX32}\", \"X-Request-Id\": \"a1b2c3d4e5f6\"}",
   "{\"X-Auth-Token\": \"<masqué par garde-secrets>\", \"X-Request-Id\": \"a1b2c3d4e5f6\"}"
  ],
  [
   "{\"user\":\"admin\",\"password\":\"{F:MDP}\",\"port\":5432}",
   "{\"user\":\"admin\",\"password\":\"<masqué par garde-secrets>\",\"port\":5432}"
  ],
  [
   "api_key: {F:HEX32}\nclient_secret: '{F:MDP}'\nclient_id: appli",
   "api_key: <masqué par garde-secrets>\nclient_secret: '<masqué par garde-secrets>'\nclient_id: appli"
  ],
  [
   "DB_PASSWORD={F:MDP}\nDB_USER=appli",
   "DB_PASSWORD=<masqué par garde-secrets>\nDB_USER=appli"
  ],
  [
   "postgres --password={F:MDP} --port 5432",
   "postgres --password=<masqué par garde-secrets> --port 5432"
  ],
  [
   "{'apiKey': '{F:HEX32}', 'timeout': 30}",
   "{'apiKey': '<masqué par garde-secrets>', 'timeout': 30}"
  ],
  [
   "jeton : {F:GITHUB} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:AWS} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:GITLAB} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:SLACK} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:ANTHROPIC} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:OPENAI} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:GOOGLE} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:STRIPE} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:VAULT} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:NPM} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:SCW} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "jeton : {F:JWT} (fin)",
   "jeton : <masqué par garde-secrets> (fin)"
  ],
  [
   "https://hooks.slack.com/services/{F:SLACK_WEBHOOK}",
   "https://<masqué par garde-secrets>"
  ],
  [
   "avant\n{F:CLE}\naprès",
   "avant\n<masqué par garde-secrets>\naprès"
  ],
  [
   "sortie coupée :\n{F:CLE_TRONQUEE}",
   "sortie coupée :\n<masqué par garde-secrets>"
  ]
 ],
 "intact": [
  "http://hote:9696/1/api?t=movie&apikey=<masqué par garde-secrets>&offset=0",
  "> Authorization: Bearer <masqué par garde-secrets>",
  "{\"password\":\"<masqué par garde-secrets>\"}",
  "postgres://appli:<masqué par garde-secrets>@db.example.com/base",
  "token_url=https://auth.example.com/oauth2/token",
  "password_file=/run/secrets/x",
  "apikey=${API_KEY}",
  "https://example.com/api?apikey=${API_KEY}&page=2",
  "curl -H \"Authorization: Bearer $API_TOKEN\" https://example.com",
  "Authorization: Bearer <jeton>",
  "Pour régler la clé, écris key=value dans le fichier de configuration.",
  "-rw------- 1 user user   64 oct.  3 10:00 secrets.txt\ndrwxr-xr-x 2 user user 4096 oct.  3 10:00 tokens",
  "{\"id\":42,\"title\":\"Film\",\"tmdbId\":603,\"monitored\":true,\"path\":\"/films/Film (1999)\"}",
  "{\"access_token_type\":\"Bearer\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
  "password: ********",
  "password: \"\"",
  "https://example.com/recherche?q=chat&page=2&tri=date",
  "ssh://git@git.example.com:2222/depot.git",
  "max_tokens: 4096\nTOKEN_TTL=3600s\npasswordless: true",
  "Tokenizer: modele-de-base",
  "git clone https://git.example.com/exemple/depot.git"
 ]
}
