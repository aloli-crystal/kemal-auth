# gaya-auth

Bibliothèque d'authentification Crystal pour les applications Gaya.

## Fonctionnalités

| Module | Description |
|--------|-------------|
| `GayaAuth::Password` | Hachage et validation BCrypt des mots de passe |
| `GayaAuth::Token` | Génération et vérification de tokens JWT |
| `GayaAuth::Session` | Gestion des sessions via cookies HTTP (Kemal) |
| `GayaAuth::SmtpConfig` | Configuration du serveur SMTP (paramétrable) |
| `GayaAuth::PasswordReset` | Récupération de mot de passe par courriel |
| `GayaAuth::UserManager` | Gestion des utilisateurs administrateurs |

## Installation

Ajouter dans votre `shard.yml` :

```yaml
dependencies:
  gaya_auth:
    github: aloli/gaya-auth
    branch: developpement
```

Puis exécuter :

```bash
shards install
```

## Configuration SMTP

La configuration SMTP peut être fournie de trois manières, par ordre de priorité :

**1. A l'instanciation (priorité maximale) :**
```crystal
smtp = GayaAuth::SmtpConfig.new(
  host: "smtp.example.com",
  port: 587,
  username: "user@example.com",
  password: "secret",
  from_address: "noreply@gaya.fr",
  from_name: "La Table de Gaya",
  use_starttls: true
)
```

**2. Depuis un Hash (ex. : base de données) :**
```crystal
smtp = GayaAuth::SmtpConfig.from_hash({
  "smtp_host"         => "smtp.example.com",
  "smtp_port"         => "587",
  "smtp_username"     => "user@example.com",
  "smtp_password"     => "secret",
  "smtp_from_address" => "noreply@gaya.fr",
  "smtp_from_name"    => "La Table de Gaya"
})
```

**3. Via variables d'environnement (valeurs par défaut) :**

| Variable | Description | Defaut |
|----------|-------------|--------|
| `SMTP_HOST` | Hote du serveur SMTP | `localhost` |
| `SMTP_PORT` | Port SMTP | `587` |
| `SMTP_USERNAME` | Nom d'utilisateur | _(vide)_ |
| `SMTP_PASSWORD` | Mot de passe | _(vide)_ |
| `SMTP_FROM_ADDRESS` | Adresse d'expedition | `noreply@leschampsdegaya.com` |
| `SMTP_FROM_NAME` | Nom d'expediteur | `La Table de Gaya` |
| `SMTP_TLS` | Activer TLS/SMTPS | `false` |
| `SMTP_STARTTLS` | Activer STARTTLS | `true` |

## Utilisation

### Gestion des mots de passe

```crystal
require "gaya_auth"

hash = GayaAuth::Password.hash("MonMotDePasse1")
GayaAuth::Password.verify("MonMotDePasse1", hash) # => true
errors = GayaAuth::Password.validate("faible")
```

### Tokens JWT

```crystal
token = GayaAuth::Token.generate(
  secret: ENV["SESSION_SECRET"],
  sub: "1",
  email: "admin@gaya.fr",
  role: "admin"
)
payload = GayaAuth::Token.decode(token, ENV["SESSION_SECRET"])
```

### Recuperation de mot de passe

```crystal
smtp = GayaAuth::SmtpConfig.new(host: "smtp.example.com", ...)
result = GayaAuth::PasswordReset.send_reset_email(
  email: "admin@gaya.fr",
  reset_url: "https://app.gaya.fr/admin/reset-password",
  secret: ENV["SESSION_SECRET"],
  smtp: smtp
)
```

### Gestion des utilisateurs

```crystal
errors = GayaAuth::UserManager.validate_user(
  email: "nouveau@gaya.fr", nom: "Martin", prenom: "Sophie", role: "gestionnaire"
)
GayaAuth::UserManager.send_invitation_email(
  email: "nouveau@gaya.fr", prenom: "Sophie",
  invitation_url: "https://app.gaya.fr/admin/set-password",
  secret: ENV["SESSION_SECRET"], smtp: smtp
)
temp_pwd = GayaAuth::UserManager.generate_temp_password
```

## Tests

```bash
crystal spec
```

52 exemples couvrant tous les modules.

## Licence

MIT
