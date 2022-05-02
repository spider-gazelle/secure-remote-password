require "./helpers"

class SecureRemotePassword::Client
  include Helpers

  getter arg_N : BigInt
  getter arg_g : BigInt
  getter arg_k : BigInt
  getter arg_a : BigInt

  getter algorithm : Algorithm
  getter username : String
  getter group : Int32

  # Generated as part of the authentication flow
  getter arg_A : String = ""
  getter session_key : String = ""
  getter verifier : String = ""

  def initialize(
    @username : String,
    @password : String,
    @group : Int32 = 3072,
    @algorithm : Algorithm = Algorithm::SHA512,
    @arg_a : BigInt = random_big_int(32)
  )
    # Set N and g from initialization values.
    @arg_N, @arg_g = initialization_value(@group)

    # Pre-compute k from N and g.
    @arg_k = calculate_k
  end

  def start_authentication
    @arg_A = calculate_A(@arg_a).to_s(16)
  end

  # Process initiated authentication challenge.
  # Returns M if authentication is successful, false otherwise.
  # Salt and B should be given in hex.
  def process_challenge(server : Challenge)
    arg_B = server.proof.to_big_i(16)

    # SRP-6a safety check
    raise "ABORT: invalid server proof" if (arg_B % @arg_N) == 0

    u = calculate_u(@arg_A, server.proof)

    # SRP-6a safety check
    raise "ABORT: invalid server proof" if u == 0

    # calculate session key
    @session_key = calculate_client_S(arg_B, server.salt, u, arg_a).to_s(16)
    big_k = hash_hex(@session_key)

    # calculate match
    match = calculate_M(@username, server.salt, @arg_A, server.proof, big_k).to_s(16)

    # calculate verifier
    @verifier = calculate_h_amk(@arg_A, match, big_k).to_s(16)

    # we send this to the server with our username
    match
  end

  # The server returns it's generated H(AMK) and we check it matches ours
  def verify(server_h_amk)
    return false unless @verifier.presence
    @verifier == server_h_amk
  end
end
