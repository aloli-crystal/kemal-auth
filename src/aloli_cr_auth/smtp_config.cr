module AloliCrAuth
  # Configuration du serveur SMTP pour l'envoi de courriels.
  # Toutes les valeurs sont paramétrables à l'instanciation ou
  # via les variables d'environnement correspondantes.
  #
  # ```
  # config = AloliCrAuth::SmtpConfig.new(
  #   host: "smtp.example.com",
  #   port: 587,
  #   username: "user@example.com",
  #   password: "secret",
  #   from_address: "noreply@example.com",
  #   from_name: "La Table de Gaya"
  # )
  # ```
  class SmtpConfig
    property host : String
    property port : Int32
    property username : String
    property password : String
    property from_address : String
    property from_name : String
    property use_tls : Bool
    property use_starttls : Bool

    def initialize(
      @host : String = ENV.fetch("SMTP_HOST", "localhost"),
      @port : Int32 = ENV.fetch("SMTP_PORT", "587").to_i,
      @username : String = ENV.fetch("SMTP_USERNAME", ""),
      @password : String = ENV.fetch("SMTP_PASSWORD", ""),
      @from_address : String = ENV.fetch("SMTP_FROM_ADDRESS", "noreply@leschampsdegaya.com"),
      @from_name : String = ENV.fetch("SMTP_FROM_NAME", "La Table de Gaya"),
      @use_tls : Bool = ENV.fetch("SMTP_TLS", "false") == "true",
      @use_starttls : Bool = ENV.fetch("SMTP_STARTTLS", "true") == "true"
    )
    end

    # Crée une configuration depuis un Hash de paramètres.
    # Utile pour charger la configuration depuis une base de données.
    #
    # ```
    # config = AloliCrAuth::SmtpConfig.from_hash({
    #   "smtp_host"     => "smtp.example.com",
    #   "smtp_port"     => "587",
    #   "smtp_username" => "user@example.com",
    #   "smtp_password" => "secret"
    # })
    # ```
    def self.from_hash(params : Hash(String, String)) : SmtpConfig
      new(
        host: params.fetch("smtp_host", ENV.fetch("SMTP_HOST", "localhost")),
        port: params.fetch("smtp_port", ENV.fetch("SMTP_PORT", "587")).to_i,
        username: params.fetch("smtp_username", ENV.fetch("SMTP_USERNAME", "")),
        password: params.fetch("smtp_password", ENV.fetch("SMTP_PASSWORD", "")),
        from_address: params.fetch("smtp_from_address", ENV.fetch("SMTP_FROM_ADDRESS", "noreply@leschampsdegaya.com")),
        from_name: params.fetch("smtp_from_name", ENV.fetch("SMTP_FROM_NAME", "La Table de Gaya")),
        use_tls: params.fetch("smtp_tls", ENV.fetch("SMTP_TLS", "false")) == "true",
        use_starttls: params.fetch("smtp_starttls", ENV.fetch("SMTP_STARTTLS", "true")) == "true"
      )
    end

    # Valide que la configuration minimale est présente.
    # Retourne un tableau de messages d'erreur (vide si valide).
    def validate : Array(String)
      errors = [] of String
      errors << "L'hôte SMTP ne peut pas être vide" if host.empty?
      errors << "Le port SMTP doit être entre 1 et 65535" unless (1..65535).includes?(port)
      errors << "L'adresse d'expédition ne peut pas être vide" if from_address.empty?
      errors << "L'adresse d'expédition est invalide" unless from_address.includes?("@")
      errors
    end

    def valid? : Bool
      validate.empty?
    end

    def to_s : String
      "SmtpConfig(host=#{host}, port=#{port}, from=#{from_address}, tls=#{use_tls}, starttls=#{use_starttls})"
    end
  end
end
