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
    @username,
    @password,
    @group : Int32,
    @algorithm : Algorithm = Algorithm::SHA512,
    salt_size : Int32? = nil
  )
    @salt_size = salt_size || case @algorithm
                              in .sha1?
                                10
                              in .sha512?
                                16
                              end

    # Set N and g from initialization values.
    @arg_N, @arg_g = initialization_value(@group)

    # Pre-compute k from N and g.
    @arg_k = calculate_k
    @arg_a = random_big_int(32)
  end

  def start_authentication
    @arg_A = calculate_A(@arg_a, @arg_N, @arg_g).to_s(16)
  end

  # Process initiated authentication challenge.
  # Returns M if authentication is successful, false otherwise.
  # Salt and B should be given in hex.
  def process_challenge(server_salt : String, server_proof_B : String)
    bb = server_proof_B.to_big_i(16)

    # SRP-6a safety check
    raise "ABORT: invalid server proof" if (bb % @arg_N) == 0

    x = calculate_x(server_salt)
    u = calculate_u(@arg_A, server_proof_B)

    # SRP-6a safety check
    raise "ABORT: invalid server proof" if u == 0

    # calculate session key
    @session_key = calculate_client_S(bb, @arg_a, @arg_k, x, u, @arg_N, @arg_g).to_s(16)
    big_k = hash_hex(@session_key)

    # calculate match
    match = calculate_M(server_salt, @arg_A, server_proof_B, big_k).to_s(16)

    # calculate verifier
    @verifier = srp.calc_h_amk(@big_a, match, @big_k, @n).to_s(16)

    # we send this to the server with our username
    match
  end

  # The server returns it's generated H(AMK) and we check it matches ours
  def verify(server_hamk)
    return false unless @verifier.presence
    @verifier == server_hamk
  end
end
