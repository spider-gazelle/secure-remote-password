require "json"

struct SecureRemotePassword::Challenge
  include JSON::Serializable

  getter proof : String
  getter salt : String

  def initialize(@proof, @salt)
  end
end
