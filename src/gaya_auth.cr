require "./gaya_auth/password"
require "./gaya_auth/token"
require "./gaya_auth/session"
require "./gaya_auth/smtp_config"
require "./gaya_auth/password_reset"
require "./gaya_auth/user_manager"

# GayaAuth — Bibliothèque d'authentification pour les applications Gaya
#
# Modules disponibles :
# - `GayaAuth::Password`      — Hachage et validation BCrypt des mots de passe
# - `GayaAuth::Token`         — Génération et vérification de tokens JWT
# - `GayaAuth::Session`       — Gestion des sessions via cookies HTTP (Kemal)
# - `GayaAuth::SmtpConfig`    — Configuration du serveur SMTP
# - `GayaAuth::PasswordReset` — Récupération de mot de passe par courriel
# - `GayaAuth::UserManager`   — Gestion des utilisateurs administrateurs
#
# ## Utilisation rapide
#
# ```crystal
# require "gaya_auth"
#
# # Configuration SMTP
# smtp = GayaAuth::SmtpConfig.new(
#   host: "smtp.example.com",
#   port: 587,
#   username: "user@example.com",
#   password: "secret",
#   from_address: "noreply@gaya.fr",
#   from_name: "La Table de Gaya"
# )
#
# # Hachage d'un mot de passe
# hash = GayaAuth::Password.hash("MonMotDePasse1")
#
# # Vérification
# GayaAuth::Password.verify("MonMotDePasse1", hash) # => true
#
# # Génération d'un token JWT
# token = GayaAuth::Token.generate(
#   secret: ENV["SESSION_SECRET"],
#   sub: "1",
#   email: "admin@gaya.fr"
# )
#
# # Envoi d'un courriel de réinitialisation
# GayaAuth::PasswordReset.send_reset_email(
#   email: "admin@gaya.fr",
#   reset_url: "https://app.gaya.fr/admin/reset-password",
#   secret: ENV["SESSION_SECRET"],
#   smtp: smtp
# )
# ```
module GayaAuth
  VERSION = "0.1.0"
end
