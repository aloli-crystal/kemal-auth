require "./crystal_kemal_auth/password"
require "./crystal_kemal_auth/token"
require "./crystal_kemal_auth/session"
require "./crystal_kemal_auth/smtp_config"
require "./crystal_kemal_auth/password_reset"
require "./crystal_kemal_auth/user_manager"

# CrystalKemalAuth — Bibliothèque d'authentification pour les applications Gaya
#
# Modules disponibles :
# - `CrystalKemalAuth::Password`      — Hachage et validation BCrypt des mots de passe
# - `CrystalKemalAuth::Token`         — Génération et vérification de tokens JWT
# - `CrystalKemalAuth::Session`       — Gestion des sessions via cookies HTTP (Kemal)
# - `CrystalKemalAuth::SmtpConfig`    — Configuration du serveur SMTP
# - `CrystalKemalAuth::PasswordReset` — Récupération de mot de passe par courriel
# - `CrystalKemalAuth::UserManager`   — Gestion des utilisateurs administrateurs
#
# ## Utilisation rapide
#
# ```
# require "crystal_kemal_auth"
#
# # Configuration SMTP
# smtp = CrystalKemalAuth::SmtpConfig.new(
#   host: "smtp.example.com",
#   port: 587,crystal_kemal_auth
#   username: "user@example.com",
#   password: "secret",
#   from_address: "noreply@gaya.fr",
#   from_name: "La Table de Gaya"
# )
#
# # Hachage d'un mot de passe
# hash = CrystalKemalAuth::Password.hash("MonMotDePasse1")
#
# # Vérification
# CrystalKemalAuth::Password.verify("MonMotDePasse1", hash) # => true
#
# # Génération d'un token JWT
# token = CrystalKemalAuth::Token.generate(
#   secret: ENV["SESSION_SECRET"],
#   sub: "1",
#   email: "admin@gaya.fr"
# )
#
# # Envoi d'un courriel de réinitialisation
# CrystalKemalAuth::PasswordReset.send_reset_email(
#   email: "admin@gaya.fr",
#   reset_url: "https://app.gaya.fr/admin/reset-password",
#   secret: ENV["SESSION_SECRET"],
#   smtp: smtp
# )
# ```
module CrystalKemalAuth
  VERSION = "0.1.0"
end
