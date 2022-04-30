require "./srp"

class SecureRemotePassword::Client
  getter n : BigInt
  getter g : BigInt
  getter k : BigInt
  getter a : BigInt

  getter big_k : String = ""
  getter big_a : String = ""
  getter s : String = ""
  getter m : String = ""
  getter h_amk : String? = nil

  def initialize(group = 3072, algorithm : SRP::Algorithm = SRP::Algorithm::SHA512)
    @srp = srp = SRP.new(algorithm)
    # select modulus (N) and generator (g)
    @n, @g = srp.ng group
    @k = srp.calc_k(@n, @g)
    @a = srp.bigrand(32)
  end

  def start_authentication
    @big_a = @srp.calc_a(@a, @n, @g).to_s(16)
  end

  # Process initiated authentication challenge.
  # Returns M if authentication is successful, false otherwise.
  # Salt and B should be given in hex.
  def process_challenge(username : String, password : String, xsalt : String, xbb : String)
    srp = @srp
    bb = srp.to_big_int xbb
    # SRP-6a safety check
    return nil if (bb % @n) == 0

    x = srp.calc_x(username, password, xsalt)
    u = srp.calc_u(@big_a, xbb, @n)

    # SRP-6a safety check
    return nil if u == 0

    # calculate session key
    @s = srp.calc_client_s(bb, @a, @k, x, u, @n, @g).to_s(16)
    @big_k = srp.hash_hex(@s)

    # calculate match
    @m = srp.calc_m(username, xsalt, @big_a, xbb, @big_k, @n, @g).to_s(16)

    # calculate verifier
    @h_amk = srp.calc_h_amk(@big_a, @m, @big_k, @n).to_s(16)

    @m
  end

  def verify(server_hamk)
    return false unless @h_amk
    @h_amk == server_hamk
  end
end
