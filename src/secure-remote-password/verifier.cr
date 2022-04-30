require "./srp"

class SecureRemotePassword::Verifier
  def initialize(group = 3072, algorithm : SRP::Algorithm = SRP::Algorithm::SHA512)
    @srp = srp = SRP.new(algorithm)
    # select modulus (N) and generator (g)
    @n, @g = srp.ng group
    @k = srp.calc_k(@n, @g)
    @b = srp.bigrand(32)
  end

  getter n : BigInt
  getter g : BigInt
  getter k : BigInt
  getter b : BigInt
  getter u : BigInt? = nil

  getter big_k : String = ""
  getter big_b : String = ""
  getter a : String = ""
  getter s : String = ""
  getter m : String = ""
  getter h_amk : String? = nil

  private getter salt : String { @srp.bigrand_hex(@srp.salt_size) }

  # Initial user creation for the persistance layer.
  # Not part of the authentication process.
  # Returns { <username>, <password verifier>, <salt> }
  def generate_userauth(username, password)
    x = @srp.calc_x(username, password, salt)
    v = @srp.calc_v(x, @n, @g)
    {username: username, verifier: v.to_s(16), salt: salt}
  end

  # Authentication phase 1 - create challenge.
  # Returns Hash with challenge for client and proof to be stored on server.
  # Parameters should be given in hex.
  def get_challenge_and_proof(username : String, xverifier : String, xsalt : String, xaa : String? = nil)
    # SRP-6a safety check
    return nil if xaa && (@srp.to_big_int(xaa) % @n) == 0
    generate_b(xverifier)
    {
      challenge: {:B => @big_b, :salt => xsalt},
      proof:     {
        A: xaa, B: @big_b, b: @b.to_s(16),
        I: username, s: xsalt, v: xverifier,
      },
    }
  end

  # returns H_AMK on success, None on failure
  # User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
  # Host -> User:  H(A, M, K)
  def verify_session(proof, client_m : String)
    srp = @srp
    @a = proof[:A]
    @big_b = proof[:B]
    @b = srp.to_big_int proof[:b]
    username = proof[:I]
    xsalt = proof[:s]
    v = srp.to_big_int proof[:v]

    @u = u = srp.calc_u(@a, @big_b, @n)
    # SRP-6a safety check
    return nil if u == 0

    # calculate session key
    @s = srp.calc_server_s(srp.to_big_int(@a), @b, v, u, @n).to_s(16)
    @big_k = srp.hash_hex(@s)

    # calculate match
    @m = srp.calc_m(username, xsalt, @a, @big_b, @big_k, @n, @g).to_s(16)

    if @m == client_m
      # authentication succeeded
      @h_amk = srp.calc_h_amk(@a, @m, @big_k, @n).to_s(16)
      return @h_amk
    end
    nil
  end

  # generates challenge
  # input verifier in hex
  def generate_b(xverifier : String)
    v = SRP.to_big_int(xverifier)
    @big_b = @srp.calc_b(@b, k, v, @n, @g).to_s(16)
  end
end
