require "json"

struct SecureRemotePassword::Proof
  include JSON::Serializable

  getter client_A : String
  getter arg_B : String
  getter arg_b : String
  getter username : String
  getter salt : String
  getter verifier : String

  def initialize(@client_A, @arg_B, @arg_b, @username, @salt, @verifier)
  end
end
