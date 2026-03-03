require "bcrypt"

module KemalAuth
  # Gestion sécurisée des mots de passe via BCrypt.
  # Encapsule le hachage et la vérification des mots de passe
  # avec un coût configurable.
  module Password
    # Coût BCrypt par défaut (12 = bon compromis sécurité/performance)
    DEFAULT_COST = 12

    # Hache un mot de passe en clair et retourne le hash BCrypt.
    #
    # ```
    # hash = KemalAuth::Password.hash("mon_mot_de_passe")
    # ```
    def self.hash(plain_password : String, cost : Int32 = DEFAULT_COST) : String
      raise ArgumentError.new("Le mot de passe ne peut pas être vide") if plain_password.empty?
      raise ArgumentError.new("Le mot de passe doit contenir au moins 8 caractères") if plain_password.size < 8
      BCrypt::Password.create(plain_password, cost: cost).to_s
    end

    # Vérifie la robustesse d'un mot de passe.
    # Retourne un tableau de messages d'erreur (vide si valide).
    #
    # ```
    # errors = KemalAuth::Password.validate("abc")
    # # => ["Le mot de passe doit contenir au moins 8 caractères"]
    # ```
    def self.validate(plain_password : String) : Array(String)
      errors = [] of String
      errors << "Le mot de passe ne peut pas être vide" if plain_password.empty?
      errors << "Le mot de passe doit contenir au moins 8 caractères" if plain_password.size < 8
      errors << "Le mot de passe doit contenir au moins une majuscule" unless plain_password.matches?(/[A-Z]/)
      errors << "Le mot de passe doit contenir au moins un chiffre" unless plain_password.matches?(/[0-9]/)
      errors
    end

    # Retourne true si le mot de passe respecte toutes les règles de robustesse.
    def self.valid?(plain_password : String) : Bool
      validate(plain_password).empty?
    end

    # Vérifie qu'un mot de passe en clair correspond au hash BCrypt stocké.
    #
    # ```
    # KemalAuth::Password.verify("mon_mot_de_passe", stored_hash) # => true ou false
    # ```
    def self.verify(plain_password : String, hashed_password : String) : Bool
      return false if plain_password.empty? || hashed_password.empty?
      BCrypt::Password.new(hashed_password).verify(plain_password)
    rescue
      false
    end
  end
end
