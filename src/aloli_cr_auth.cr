require "./aloli_cr_auth/password"
require "./aloli_cr_auth/token"
require "./aloli_cr_auth/session"
require "./aloli_cr_auth/smtp_config"
require "./aloli_cr_auth/password_reset"
require "./aloli_cr_auth/user_manager"

# AloliCrAuth — Bibliothèque d'authentification pour les applications Gaya
#
# Modules disponibles :
# - `AloliCrAuth::Password`      — Hachage et validation BCrypt des mots de passe
# - `AloliCrAuth::Token`         — Génération et vérification de tokens JWT
# - `AloliCrAuth::Session`       — Gestion des sessions via cookies HTTP (Kemal)
# - `AloliCrAuth::SmtpConfig`    — Configuration du serveur SMTP
# - `AloliCrAuth::PasswordReset` — Récupération de mot de passe par courriel
# - `AloliCrAuth::UserManager`   — Gestion des utilisateurs administrateurs
#
# ## Utilisation rapide
#
# ```crystal
# require "aloli_cr_auth"
#
# # Configuration SMTP
# smtp = AloliCrAuth::SmtpConfig.new(
#   host: "smtp.example.com",
#   port: 587,
#   username: "user@example.com",
#   password: "secret",
#   from_address: "noreply@gaya.fr",
#   from_name: "La Table de Gaya"
# )
#
# # Hachage d'un mot de passe
# hash = AloliCrAuth::Password.hash("MonMotDePasse1")
#
# # Vérification
# AloliCrAuth::Password.verify("MonMotDePasse1", hash) # => true
#
# # Génération d'un token JWT
# token = AloliCrAuth::Token.generate(
#   secret: ENV["SESSION_SECRET"],
#   sub: "1",
#   email: "admin@gaya.fr"
# )
#
# # Envoi d'un courriel de réinitialisation
# AloliCrAuth::PasswordReset.send_reset_email(
#   email: "admin@gaya.fr",
#   reset_url: "https://app.gaya.fr/admin/reset-password",
#   secret: ENV["SESSION_SECRET"],
#   smtp: smtp
# )
# ```
module AloliCrAuth
  VERSION = "0.1.0"
end
