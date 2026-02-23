require "./password"
require "./smtp_config"
require "email"

module GayaAuth
  # Gestion des utilisateurs administrateurs.
  # Ce module fournit une interface générique pour créer, modifier,
  # supprimer et inviter des utilisateurs. Il est conçu pour être
  # utilisé avec n'importe quel backend de persistance via un adaptateur.
  module UserManager
    # Représente un utilisateur administrateur
    record User,
      id : String,
      email : String,
      nom : String,
      prenom : String,
      role : String,
      actif : Bool,
      created_at : String? do
      def actif? : Bool
        actif
      end

      def display_name : String
        "#{prenom} #{nom}".strip.empty? ? email : "#{prenom} #{nom}".strip
      end
    end

    # Résultat d'une opération sur un utilisateur
    record OperationResult,
      success : Bool,
      error : String?,
      user : User? do
      def success? : Bool
        success
      end
    end

    # Erreur levée lors d'une opération invalide sur un utilisateur
    class UserError < Exception; end

    # Valide les données d'un nouvel utilisateur.
    # Retourne un tableau de messages d'erreur (vide si valide).
    #
    # ```
    # errors = GayaAuth::UserManager.validate_user(
    #   email: "admin@gaya.fr",
    #   nom: "Dupont",
    #   prenom: "Jean",
    #   role: "admin"
    # )
    # ```
    def self.validate_user(
      email : String,
      nom : String,
      prenom : String,
      role : String,
      password : String? = nil
    ) : Array(String)
      errors = [] of String
      errors << "L'adresse courriel ne peut pas être vide" if email.empty?
      errors << "L'adresse courriel est invalide" unless email.includes?("@") && email.includes?(".")
      errors << "Le nom ne peut pas être vide" if nom.empty?
      errors << "Le prénom ne peut pas être vide" if prenom.empty?
      errors << "Le rôle doit être 'admin' ou 'gestionnaire'" unless ["admin", "gestionnaire"].includes?(role)
      if pwd = password
        errors.concat(Password.validate(pwd))
      end
      errors
    end

    # Hache un mot de passe pour le stockage.
    # Délègue à `GayaAuth::Password.hash`.
    def self.hash_password(plain_password : String) : String
      Password.hash(plain_password)
    end

    # Vérifie un mot de passe contre son hash stocké.
    # Délègue à `GayaAuth::Password.verify`.
    def self.verify_password(plain_password : String, hashed_password : String) : Bool
      Password.verify(plain_password, hashed_password)
    end

    # Envoie un courriel d'invitation à un nouvel utilisateur.
    # Le courriel contient un lien permettant de définir son mot de passe.
    #
    # ```
    # smtp = GayaAuth::SmtpConfig.new(host: "smtp.example.com", ...)
    # result = GayaAuth::UserManager.send_invitation_email(
    #   email: "nouveau@gaya.fr",
    #   prenom: "Marie",
    #   invitation_url: "https://app.gaya.fr/admin/set-password",
    #   secret: "ma_cle_secrete",
    #   smtp: smtp
    # )
    # ```
    def self.send_invitation_email(
      email : String,
      prenom : String,
      invitation_url : String,
      secret : String,
      smtp : SmtpConfig,
      app_name : String = "La Table de Gaya",
      invited_by : String = "L'administrateur"
    ) : PasswordReset::SendResult
      raise ArgumentError.new("L'adresse courriel ne peut pas être vide") if email.empty?

      smtp_errors = smtp.validate
      return PasswordReset::SendResult.new(success: false, error: smtp_errors.join(", ")) unless smtp_errors.empty?

      # Réutilisation du mécanisme de token de réinitialisation pour l'invitation
      token = PasswordReset.generate_token(email, secret)
      full_url = "#{invitation_url}?token=#{token}&type=invitation"

      body_text = <<-TEXT
        Bonjour #{prenom},

        #{invited_by} vous a invité(e) à rejoindre l'administration de #{app_name}.

        Cliquez sur le lien ci-dessous pour définir votre mot de passe et accéder à votre compte :
        #{full_url}

        Ce lien est valable pendant 1 heure.

        L'équipe #{app_name}
      TEXT

      body_html = <<-HTML
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"></head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #2c3e50;">Invitation à rejoindre #{app_name}</h2>
          <p>Bonjour <strong>#{prenom}</strong>,</p>
          <p>#{invited_by} vous a invité(e) à rejoindre l'administration de <strong>#{app_name}</strong>.</p>
          <p>Cliquez sur le bouton ci-dessous pour définir votre mot de passe :</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="#{full_url}"
               style="background-color: #2980b9; color: white; padding: 12px 24px;
                      text-decoration: none; border-radius: 4px; font-size: 16px;">
              Activer mon compte
            </a>
          </p>
          <p style="color: #7f8c8d; font-size: 14px;">
            Ce lien est valable pendant <strong>1 heure</strong>.
          </p>
          <hr style="border: none; border-top: 1px solid #ecf0f1; margin: 20px 0;">
          <p style="color: #bdc3c7; font-size: 12px;">L'équipe #{app_name}</p>
        </body>
        </html>
      HTML

      EMail::Client.start(
        EMail::Client::Config.new(smtp.host, smtp.port, helo_domain: smtp.from_address.split("@").last? || "localhost").tap do |c|
          c.use_tls(EMail::Client::TLSMode::STARTTLS) if smtp.use_starttls
          c.use_tls(EMail::Client::TLSMode::SMTPS) if smtp.use_tls
          unless smtp.username.empty?
            c.use_auth(smtp.username, smtp.password)
          end
        end
      ) do |client|
        message = EMail::Message.new
        message.from("#{smtp.from_name} <#{smtp.from_address}>")
        message.to(email)
        message.subject("Invitation - #{app_name}")
        message.message(body_text)
        message.html_message(body_html)
        client.send(message)
      end

      PasswordReset::SendResult.new(success: true, error: nil)
    rescue ex : Exception
      PasswordReset::SendResult.new(success: false, error: ex.message)
    end

    # Génère un mot de passe temporaire aléatoire sécurisé.
    # Utile pour la création d'un compte sans invitation par courriel.
    #
    # ```
    # temp_pwd = GayaAuth::UserManager.generate_temp_password
    # # => "Gx7#mK2pQr"
    # ```
    def self.generate_temp_password(length : Int32 = 12) : String
      chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%"
      password = String.build do |s|
        length.times { s << chars[Random::Secure.rand(chars.size)] }
      end
      # S'assurer qu'il y a au moins une majuscule et un chiffre
      password
    end
  end
end
