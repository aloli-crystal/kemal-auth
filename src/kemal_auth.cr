require "./kemal_auth/password"
require "./kemal_auth/token"
require "./kemal_auth/session"
require "./kemal_auth/smtp_config"
require "./kemal_auth/password_reset"
require "./kemal_auth/user_manager"

# KemalAuth — Bibliothèque d'authentification pour les applications Gaya
#
# Modules disponibles :
# - `KemalAuth::Password`      — Hachage et validation BCrypt des mots de passe
# - `KemalAuth::Token`         — Génération et vérification de tokens JWT
# - `KemalAuth::Session`       — Gestion des sessions via cookies HTTP (Kemal)
# - `KemalAuth::SmtpConfig`    — Configuration du serveur SMTP
# - `KemalAuth::PasswordReset` — Récupération de mot de passe par courriel
# - `KemalAuth::UserManager`   — Gestion des utilisateurs administrateurs
#
# ## Utilisation rapide
#
# ```
# require "kemal_auth"
#
# # Configuration SMTP
# smtp = KemalAuth::SmtpConfig.new(
#   host: "smtp.example.com",
#   port: 587,kemal_auth
#   username: "user@example.com",
#   password: "secret",
#   from_address: "noreply@gaya.fr",
#   from_name: "La Table de Gaya"
# )
#
# # Hachage d'un mot de passe
# hash = KemalAuth::Password.hash("MonMotDePasse1")
#
# # Vérification
# KemalAuth::Password.verify("MonMotDePasse1", hash) # => true
#
# # Génération d'un token JWT
# token = KemalAuth::Token.generate(
#   secret: ENV["SESSION_SECRET"],
#   sub: "1",
#   email: "admin@gaya.fr"
# )
#
# # Envoi d'un courriel de réinitialisation
# KemalAuth::PasswordReset.send_reset_email(
#   email: "admin@gaya.fr",
#   reset_url: "https://app.gaya.fr/admin/reset-password",
#   secret: ENV["SESSION_SECRET"],
#   smtp: smtp
# )
# ```
module KemalAuth
  # Lue au compile-time depuis `shard.yml` via le macro `read_file`.
  # Cf. note mémoire `feedback_shard_version_macro.md` (mémoire ALOLI).
  VERSION = {{
              (read_file("#{__DIR__}/../shard.yml")
                .lines
                .find(&.starts_with?("version:")) || "version: 0.0.0")
                .gsub(/^version:\s*/, "")
                .chomp
            }}
end
