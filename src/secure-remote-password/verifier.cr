require "./challenge"
require "./helpers"
require "./proof"

class SecureRemotePassword::Verifier
  include Helpers

  getter arg_N : BigInt
  getter arg_g : BigInt
  getter arg_k : BigInt

  getter algorithm : Algorithm

  def initialize(
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
  end

  # Initial user creation for the persistance layer.
  # Not part of the authentication process. Salt should only be provided for testing
  # Returns { <username>, <password verifier>, <salt> }
  def generate_user_verifier(username : String, password : String, salt = random_hex(@salt_size))
    {username: username, verifier: calculate_v(username, password, salt).to_s(16), salt: salt}
  end

  # Authentication phase 1 - create challenge.
  # Returns Hash with challenge for client and proof to be stored on server.
  # Parameters should be given in hex.
  def get_challenge_and_proof(username : String, verifier : String, salt : String, client_A : String, arg_b : BigInt = random_big_int(32))
    # SRP-6a safety check
    raise "ABORT: invalid client A" if (client_A.to_big_i(16) % @arg_N) == 0
    arg_B = calculate_B(arg_b, verifier.to_big_i(16)).to_s(16)
    {
      # Provide this to the client
      Challenge.new(proof: arg_B, salt: salt),

      # Store this for verifying the current session
      Proof.new(
        client_A: client_A,
        arg_B: arg_B,
        arg_b: arg_b.to_s(16),
        username: username,
        verifier: verifier,
        salt: salt
      ),
    }
  end

  # returns H_AMK on success, None on failure
  # User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
  # Host -> User:  H(A, M, K)
  def verify_session(proof : Proof, client_m : String)
    u = calculate_u(proof.client_A, proof.arg_B)
    # SRP-6a safety check
    raise "ABORT: illegal_parameter u" if u == 0

    # calculate session key
    arg_S = calculate_server_S(
      proof.client_A.to_big_i(16),
      proof.verifier.to_big_i(16),
      u,
      proof.arg_b.to_big_i(16)
    ).to_s(16)
    arg_K = hash_hex(arg_S)

    # calculate match
    match = calculate_M(proof.username, proof.salt, proof.client_A, proof.arg_B, arg_K).to_s(16)

    return nil unless match == client_m
    calculate_h_amk(proof.client_A, match, arg_K).to_s(16)
  end
end
