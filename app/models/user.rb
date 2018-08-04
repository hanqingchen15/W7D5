class User < ApplicationRecord
  validates :username, presence:true, uniqueness:true
  validates :password_digest, presence:true
  validates :password, length:{ minimum: 6, allow_nil:true }

  after_initialize :ensure_session_token

  attr_reader :password

  def self.find_by_credentials(username, password)
    user = User.find_by(username: username)
    if user
      return user if user.is_password?(password)
    else
      return nil
    end
  end

  def ensure_session_token
    self.session_token ||= SecureRandom.urlsafe_base64
  end

  def reset_session_token!
    self.session_token = SecureRandom.urlsafe_base64
    self.save!
    return self.session_token
  end

  def password=(password)
    @password = password
    self.password_digest = BCrypt::Password.create(password)
  end

  def is_password?(password)
    BCrypt::Password.new(self.password_digest).is_password?(password)
  end

end
