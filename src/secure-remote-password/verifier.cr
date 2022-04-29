require "./srp"

class SecureRemotePassword::Verifier
  def initialize(group = 1024)
    # select modulus (N) and generator (g)
    @n, @g = SRP.ng group
    @k = SRP.calc_k(@n, @g)
    @b = SRP.bigrand(32)
  end

  getter n : BigInt
  getter g : BigInt
  getter k : BigInt
  getter b : BigInt

  getter big_k : String = ""
  getter big_b : String = ""
  getter a : String = ""
  getter s : String = ""
  getter m : String = ""
  getter h_amk : String? = nil

  private getter salt : String { SRP.bigrand_hex(10) }

  # Initial user creation for the persistance layer.
  # Not part of the authentication process.
  # Returns { <username>, <password verifier>, <salt> }
  def generate_userauth(username, password)
    x = SRP.calc_x(username, password, salt)
    v = SRP.calc_v(x, @n, @g)
    {username: username, verifier: v.to_s(16), salt: salt}
  end

  # Authentication phase 1 - create challenge.
  # Returns Hash with challenge for client and proof to be stored on server.
  # Parameters should be given in hex.
  def get_challenge_and_proof(username : String, xverifier : String, xsalt : String, xaa : String)
    # SRP-6a safety check
    return nil if (SRP.to_big_int(xaa) % @n) == 0
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
    @a = proof[:A]
    @big_b = proof[:B]
    @b = SRP.to_big_int proof[:b]
    username = proof[:I]
    xsalt = proof[:s]
    v = SRP.to_big_int proof[:v]

    u = SRP.calc_u(@a, @big_b, @n)
    # SRP-6a safety check
    return nil if u == 0

    # calculate session key
    @s = SRP.calc_server_s(SRP.to_big_int(@a), @b, v, u, @n).to_s(16)
    @big_k = SRP.sha1_hex(@s)

    # calculate match
    @m = SRP.calc_m(username, xsalt, @a, @big_b, @big_k, @n, @g).to_s(16)

    if @m == client_m
      # authentication succeeded
      @h_amk = SRP.calc_h_amk(@a, @m, @big_k, @n, @g).to_s(16)
      return @h_amk
    end
    nil
  end

  # generates challenge
  # input verifier in hex
  def generate_b(xverifier : String)
    v = SRP.to_big_int(xverifier)
    @big_b = SRP.calc_b(@b, k, v, @n, @g).to_s(16)
  end
end
