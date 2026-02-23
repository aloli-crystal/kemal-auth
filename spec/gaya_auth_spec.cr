require "./spec_helper"

# =============================================================================
# Tests GayaAuth::Password
# =============================================================================
describe GayaAuth::Password do
  describe ".hash" do
    it "hache un mot de passe valide" do
      hash = GayaAuth::Password.hash(TEST_PASSWORD)
      hash.should_not be_empty
      hash.should start_with("$2")
    end

    it "produit des hashes différents pour le même mot de passe" do
      hash1 = GayaAuth::Password.hash(TEST_PASSWORD)
      hash2 = GayaAuth::Password.hash(TEST_PASSWORD)
      hash1.should_not eq(hash2)
    end

    it "lève une erreur si le mot de passe est vide" do
      expect_raises(ArgumentError, "vide") do
        GayaAuth::Password.hash("")
      end
    end

    it "lève une erreur si le mot de passe est trop court" do
      expect_raises(ArgumentError, "8 caractères") do
        GayaAuth::Password.hash("abc")
      end
    end
  end

  describe ".verify" do
    it "retourne true pour un mot de passe correct" do
      hash = GayaAuth::Password.hash(TEST_PASSWORD)
      GayaAuth::Password.verify(TEST_PASSWORD, hash).should be_true
    end

    it "retourne false pour un mot de passe incorrect" do
      hash = GayaAuth::Password.hash(TEST_PASSWORD)
      GayaAuth::Password.verify("MauvaisMotDePasse1", hash).should be_false
    end

    it "retourne false si le mot de passe est vide" do
      hash = GayaAuth::Password.hash(TEST_PASSWORD)
      GayaAuth::Password.verify("", hash).should be_false
    end

    it "retourne false si le hash est vide" do
      GayaAuth::Password.verify(TEST_PASSWORD, "").should be_false
    end

    it "retourne false pour un hash malformé" do
      GayaAuth::Password.verify(TEST_PASSWORD, "hash_invalide").should be_false
    end
  end

  describe ".validate" do
    it "retourne un tableau vide pour un mot de passe valide" do
      GayaAuth::Password.validate(TEST_PASSWORD).should be_empty
    end

    it "signale un mot de passe vide" do
      errors = GayaAuth::Password.validate("")
      errors.should_not be_empty
    end

    it "signale un mot de passe trop court" do
      errors = GayaAuth::Password.validate("Ab1")
      errors.any? { |e| e.includes?("8 caractères") }.should be_true
    end

    it "signale l'absence de majuscule" do
      errors = GayaAuth::Password.validate("motdepasse1")
      errors.any? { |e| e.includes?("majuscule") }.should be_true
    end

    it "signale l'absence de chiffre" do
      errors = GayaAuth::Password.validate("MotDePasseSansChiffre")
      errors.any? { |e| e.includes?("chiffre") }.should be_true
    end
  end

  describe ".valid?" do
    it "retourne true pour un mot de passe valide" do
      GayaAuth::Password.valid?(TEST_PASSWORD).should be_true
    end

    it "retourne false pour un mot de passe invalide" do
      GayaAuth::Password.valid?("court").should be_false
    end
  end
end

# =============================================================================
# Tests GayaAuth::Token
# =============================================================================
describe GayaAuth::Token do
  describe ".generate" do
    it "génère un token JWT non vide" do
      token = GayaAuth::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      token.should_not be_empty
      token.split(".").size.should eq(3)
    end

    it "lève une erreur si la clé secrète est vide" do
      expect_raises(ArgumentError, "secrète") do
        GayaAuth::Token.generate(secret: "", sub: "1", email: TEST_EMAIL)
      end
    end

    it "lève une erreur si le sujet est vide" do
      expect_raises(ArgumentError, "sub") do
        GayaAuth::Token.generate(secret: SECRET_KEY, sub: "", email: TEST_EMAIL)
      end
    end
  end

  describe ".decode" do
    it "décode un token valide" do
      token = GayaAuth::Token.generate(secret: SECRET_KEY, sub: "42", email: TEST_EMAIL, role: "admin")
      payload = GayaAuth::Token.decode(token, SECRET_KEY)
      payload.sub.should eq("42")
      payload.email.should eq(TEST_EMAIL)
      payload.role.should eq("admin")
      payload.expired?.should be_false
    end

    it "lève InvalidTokenError pour un token vide" do
      expect_raises(GayaAuth::Token::InvalidTokenError, "vide") do
        GayaAuth::Token.decode("", SECRET_KEY)
      end
    end

    it "lève InvalidTokenError pour une mauvaise clé secrète" do
      token = GayaAuth::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      expect_raises(GayaAuth::Token::InvalidTokenError) do
        GayaAuth::Token.decode(token, "mauvaise_cle_secrete_suffisamment_longue")
      end
    end

    it "lève InvalidTokenError pour un token malformé" do
      expect_raises(GayaAuth::Token::InvalidTokenError) do
        GayaAuth::Token.decode("token.invalide.ici", SECRET_KEY)
      end
    end
  end

  describe ".valid?" do
    it "retourne true pour un token valide" do
      token = GayaAuth::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      GayaAuth::Token.valid?(token, SECRET_KEY).should be_true
    end

    it "retourne false pour un token invalide" do
      GayaAuth::Token.valid?("token_invalide", SECRET_KEY).should be_false
    end

    it "retourne false pour un token vide" do
      GayaAuth::Token.valid?("", SECRET_KEY).should be_false
    end
  end

  describe ".generate_reservation_token" do
    it "génère un token de réservation valide" do
      token = GayaAuth::Token.generate_reservation_token(
        secret: SECRET_KEY,
        reservation_token: "abc123def456"
      )
      token.should_not be_empty
      token.split(".").size.should eq(3)
    end

    it "lève une erreur si la clé secrète est vide" do
      expect_raises(ArgumentError) do
        GayaAuth::Token.generate_reservation_token(secret: "", reservation_token: "abc123")
      end
    end
  end
end

# =============================================================================
# Tests GayaAuth::SmtpConfig
# =============================================================================
describe GayaAuth::SmtpConfig do
  describe ".new" do
    it "crée une configuration avec les valeurs fournies" do
      config = GayaAuth::SmtpConfig.new(
        host: "smtp.example.com",
        port: 587,
        username: "user@example.com",
        password: "secret",
        from_address: "noreply@example.com",
        from_name: "Test"
      )
      config.host.should eq("smtp.example.com")
      config.port.should eq(587)
      config.from_address.should eq("noreply@example.com")
    end
  end

  describe ".from_hash" do
    it "crée une configuration depuis un Hash" do
      config = GayaAuth::SmtpConfig.from_hash({
        "smtp_host"         => "smtp.test.com",
        "smtp_port"         => "465",
        "smtp_from_address" => "test@test.com",
        "smtp_from_name"    => "Test App"
      })
      config.host.should eq("smtp.test.com")
      config.port.should eq(465)
    end
  end

  describe ".validate" do
    it "retourne un tableau vide pour une configuration valide" do
      config = GayaAuth::SmtpConfig.new(
        host: "smtp.example.com",
        port: 587,
        from_address: "noreply@example.com"
      )
      config.validate.should be_empty
    end

    it "signale un hôte vide" do
      config = GayaAuth::SmtpConfig.new(host: "", port: 587, from_address: "test@test.com")
      config.validate.any? { |e| e.includes?("hôte") }.should be_true
    end

    it "signale un port invalide" do
      config = GayaAuth::SmtpConfig.new(host: "smtp.test.com", port: 0, from_address: "test@test.com")
      config.validate.any? { |e| e.includes?("port") }.should be_true
    end

    it "signale une adresse d'expédition invalide" do
      config = GayaAuth::SmtpConfig.new(host: "smtp.test.com", port: 587, from_address: "invalide")
      config.validate.any? { |e| e.includes?("invalide") }.should be_true
    end
  end
end

# =============================================================================
# Tests GayaAuth::PasswordReset
# =============================================================================
describe GayaAuth::PasswordReset do
  describe ".generate_token" do
    it "génère un token de réinitialisation valide" do
      token = GayaAuth::PasswordReset.generate_token(TEST_EMAIL, SECRET_KEY)
      token.should_not be_empty
      token.split(".").size.should eq(3)
    end

    it "lève une erreur si l'email est vide" do
      expect_raises(ArgumentError, "courriel") do
        GayaAuth::PasswordReset.generate_token("", SECRET_KEY)
      end
    end

    it "lève une erreur si la clé secrète est vide" do
      expect_raises(ArgumentError, "secrète") do
        GayaAuth::PasswordReset.generate_token(TEST_EMAIL, "")
      end
    end
  end

  describe ".verify_token" do
    it "retourne l'email pour un token valide" do
      token = GayaAuth::PasswordReset.generate_token(TEST_EMAIL, SECRET_KEY)
      email = GayaAuth::PasswordReset.verify_token(token, SECRET_KEY)
      email.should eq(TEST_EMAIL)
    end

    it "lève InvalidTokenError pour un token vide" do
      expect_raises(GayaAuth::Token::InvalidTokenError, "vide") do
        GayaAuth::PasswordReset.verify_token("", SECRET_KEY)
      end
    end

    it "lève InvalidTokenError pour une mauvaise clé" do
      token = GayaAuth::PasswordReset.generate_token(TEST_EMAIL, SECRET_KEY)
      expect_raises(GayaAuth::Token::InvalidTokenError) do
        GayaAuth::PasswordReset.verify_token(token, "mauvaise_cle_suffisamment_longue_ici")
      end
    end

    it "lève InvalidTokenError pour un token JWT standard (mauvais type)" do
      token = GayaAuth::Token.generate(secret: SECRET_KEY, sub: "1", email: TEST_EMAIL)
      expect_raises(GayaAuth::Token::InvalidTokenError, "Type de token invalide") do
        GayaAuth::PasswordReset.verify_token(token, SECRET_KEY)
      end
    end
  end
end

# =============================================================================
# Tests GayaAuth::UserManager
# =============================================================================
describe GayaAuth::UserManager do
  describe ".validate_user" do
    it "retourne un tableau vide pour des données valides" do
      errors = GayaAuth::UserManager.validate_user(
        email: TEST_EMAIL,
        nom: TEST_NOM,
        prenom: TEST_PRENOM,
        role: "admin"
      )
      errors.should be_empty
    end

    it "signale un email vide" do
      errors = GayaAuth::UserManager.validate_user(
        email: "", nom: TEST_NOM, prenom: TEST_PRENOM, role: "admin"
      )
      errors.any? { |e| e.includes?("courriel") }.should be_true
    end

    it "signale un email invalide" do
      errors = GayaAuth::UserManager.validate_user(
        email: "invalide", nom: TEST_NOM, prenom: TEST_PRENOM, role: "admin"
      )
      errors.any? { |e| e.includes?("invalide") }.should be_true
    end

    it "signale un nom vide" do
      errors = GayaAuth::UserManager.validate_user(
        email: TEST_EMAIL, nom: "", prenom: TEST_PRENOM, role: "admin"
      )
      errors.any? { |e| e.includes?("nom") }.should be_true
    end

    it "signale un prénom vide" do
      errors = GayaAuth::UserManager.validate_user(
        email: TEST_EMAIL, nom: TEST_NOM, prenom: "", role: "admin"
      )
      errors.any? { |e| e.includes?("prénom") }.should be_true
    end

    it "signale un rôle invalide" do
      errors = GayaAuth::UserManager.validate_user(
        email: TEST_EMAIL, nom: TEST_NOM, prenom: TEST_PRENOM, role: "superuser"
      )
      errors.any? { |e| e.includes?("rôle") }.should be_true
    end

    it "accepte le rôle gestionnaire" do
      errors = GayaAuth::UserManager.validate_user(
        email: TEST_EMAIL, nom: TEST_NOM, prenom: TEST_PRENOM, role: "gestionnaire"
      )
      errors.should be_empty
    end

    it "valide aussi le mot de passe si fourni" do
      errors = GayaAuth::UserManager.validate_user(
        email: TEST_EMAIL, nom: TEST_NOM, prenom: TEST_PRENOM,
        role: "admin", password: "faible"
      )
      errors.should_not be_empty
    end
  end

  describe ".hash_password et .verify_password" do
    it "hache et vérifie correctement un mot de passe" do
      hash = GayaAuth::UserManager.hash_password(TEST_PASSWORD)
      GayaAuth::UserManager.verify_password(TEST_PASSWORD, hash).should be_true
      GayaAuth::UserManager.verify_password("MauvaisMotDePasse1", hash).should be_false
    end
  end

  describe ".generate_temp_password" do
    it "génère un mot de passe de la longueur demandée" do
      pwd = GayaAuth::UserManager.generate_temp_password(12)
      pwd.size.should eq(12)
    end

    it "génère des mots de passe différents à chaque appel" do
      pwd1 = GayaAuth::UserManager.generate_temp_password
      pwd2 = GayaAuth::UserManager.generate_temp_password
      pwd1.should_not eq(pwd2)
    end
  end
end
