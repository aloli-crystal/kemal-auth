require "./token"
require "./smtp_config"
require "email"

module GayaAuth
  # Gestion de la récupération de mot de passe par courriel.
  # Génère un token de réinitialisation à durée limitée et envoie
  # un courriel contenant le lien de réinitialisation via SMTP configurable.
  #
  # ```
  # smtp = GayaAuth::SmtpConfig.new(host: "smtp.example.com", ...)
  # result = GayaAuth::PasswordReset.send_reset_email(
  #   email: "admin@gaya.fr",
  #   reset_url: "https://app.gaya.fr/admin/reset-password",
  #   secret: "ma_cle_secrete",
  #   smtp: smtp
  # )
  # ```
  module PasswordReset
    # Durée de validité d'un token de réinitialisation (1 heure)
    RESET_TOKEN_EXPIRY_HOURS = 1

    # Résultat d'une opération d'envoi de courriel
    record SendResult,
      success : Bool,
      error : String? do
      def success? : Bool
        success
      end
    end

    # Génère un token de réinitialisation de mot de passe signé.
    # Ce token encode l'adresse courriel et expire après 1 heure.
    #
    # ```
    # token = GayaAuth::PasswordReset.generate_token(
    #   email: "admin@gaya.fr",
    #   secret: "ma_cle_secrete"
    # )
    # ```
    def self.generate_token(email : String, secret : String) : String
      raise ArgumentError.new("L'adresse courriel ne peut pas être vide") if email.empty?
      raise ArgumentError.new("La clé secrète ne peut pas être vide") if secret.empty?

      payload = {
        "sub"  => email,
        "type" => "password_reset",
        "exp"  => (Time.utc + RESET_TOKEN_EXPIRY_HOURS.hours).to_unix,
        "iat"  => Time.utc.to_unix
      }
      JWT.encode(payload, secret, JWT::Algorithm::HS256)
    end

    # Vérifie un token de réinitialisation et retourne l'adresse courriel associée.
    # Lève `Token::InvalidTokenError` si le token est invalide ou expiré.
    #
    # ```
    # email = GayaAuth::PasswordReset.verify_token(token, secret: "ma_cle_secrete")
    # ```
    def self.verify_token(token : String, secret : String) : String
      raise Token::InvalidTokenError.new("Le token ne peut pas être vide") if token.empty?

      payload_hash, _header = JWT.decode(token, secret, JWT::Algorithm::HS256)
      hash = payload_hash.as_h

      type = hash["type"]?.try(&.as_s)
      raise Token::InvalidTokenError.new("Type de token invalide") unless type == "password_reset"

      exp = hash["exp"]?.try(&.as_i64) || raise Token::InvalidTokenError.new("Champ 'exp' manquant")
      raise Token::InvalidTokenError.new("Le token de réinitialisation a expiré") if Time.utc.to_unix >= exp

      hash["sub"]?.try(&.as_s) || raise Token::InvalidTokenError.new("Adresse courriel manquante dans le token")
    rescue ex : JWT::ExpiredSignatureError
      raise Token::InvalidTokenError.new("Le token de réinitialisation a expiré")
    rescue ex : JWT::DecodeError
      raise Token::InvalidTokenError.new("Token invalide : #{ex.message}")
    end

    # Envoie un courriel de réinitialisation de mot de passe.
    # Le lien de réinitialisation inclut le token en paramètre.
    #
    # ```
    # smtp = GayaAuth::SmtpConfig.new(host: "smtp.example.com", port: 587, ...)
    # result = GayaAuth::PasswordReset.send_reset_email(
    #   email: "admin@gaya.fr",
    #   reset_url: "https://app.gaya.fr/admin/reset-password",
    #   secret: "ma_cle_secrete",
    #   smtp: smtp,
    #   app_name: "La Table de Gaya"
    # )
    # puts result.success? # => true
    # ```
    def self.send_reset_email(
      email : String,
      reset_url : String,
      secret : String,
      smtp : SmtpConfig,
      app_name : String = "La Table de Gaya"
    ) : SendResult
      raise ArgumentError.new("L'adresse courriel ne peut pas être vide") if email.empty?
      raise ArgumentError.new("L'URL de réinitialisation ne peut pas être vide") if reset_url.empty?

      smtp_errors = smtp.validate
      return SendResult.new(success: false, error: smtp_errors.join(", ")) unless smtp_errors.empty?

      token = generate_token(email, secret)
      full_url = "#{reset_url}?token=#{token}"

      body_text = <<-TEXT
        Bonjour,

        Vous avez demandé la réinitialisation de votre mot de passe pour #{app_name}.

        Cliquez sur le lien ci-dessous pour définir un nouveau mot de passe :
        #{full_url}

        Ce lien est valable pendant #{RESET_TOKEN_EXPIRY_HOURS} heure(s).

        Si vous n'avez pas effectué cette demande, ignorez ce message.

        L'équipe #{app_name}
      TEXT

      body_html = <<-HTML
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"></head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #2c3e50;">Réinitialisation de mot de passe</h2>
          <p>Bonjour,</p>
          <p>Vous avez demandé la réinitialisation de votre mot de passe pour <strong>#{app_name}</strong>.</p>
          <p>Cliquez sur le bouton ci-dessous pour définir un nouveau mot de passe :</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="#{full_url}"
               style="background-color: #27ae60; color: white; padding: 12px 24px;
                      text-decoration: none; border-radius: 4px; font-size: 16px;">
              Réinitialiser mon mot de passe
            </a>
          </p>
          <p style="color: #7f8c8d; font-size: 14px;">
            Ce lien est valable pendant <strong>#{RESET_TOKEN_EXPIRY_HOURS} heure(s)</strong>.
          </p>
          <p style="color: #7f8c8d; font-size: 14px;">
            Si vous n'avez pas effectué cette demande, ignorez ce message.
          </p>
          <hr style="border: none; border-top: 1px solid #ecf0f1; margin: 20px 0;">
          <p style="color: #bdc3c7; font-size: 12px;">L'équipe #{app_name}</p>
        </body>
        </html>
      HTML

      EMail::Client.start(
        EMail::Client::Config.new(smtp.host, smtp.port).tap do |c|
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
        message.subject("Réinitialisation de votre mot de passe - #{app_name}")
        message.message(body_text)
        message.html_message(body_html)
        client.send(message)
      end

      SendResult.new(success: true, error: nil)
    rescue ex : Exception
      SendResult.new(success: false, error: ex.message)
    end
  end
end
