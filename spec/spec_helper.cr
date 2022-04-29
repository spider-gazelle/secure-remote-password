require "spec"
require "../src/secure-remote-password"

class SecureRemotePassword::Verifier
  def set_b(@b : BigInt)
  end

  def set_salt(@salt : String)
  end
end

class SecureRemotePassword::Client
  def set_a(@a : BigInt)
  end
end
