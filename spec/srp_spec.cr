require "./spec_helper"

module SecureRemotePassword
  # ## Test SRP functions.
  # ## Values are from http://srp.stanford.edu/demo/demo.html
  # ## using 256 bit values.
  describe SRP do
    n = SRP.to_big_int "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3"
    g = BigInt.new 2
    username = "user"
    password = "password"
    salt = "16ccfa081895fe1ed0bb"
    a = SRP.to_big_int "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2"
    b = SRP.to_big_int "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96"

    it "should calculate k" do
      k = SRP.calc_k(n, g)
      k.to_s(16).should eq "dbe5dfe0704fee4c85ff106ecd38117d33bcfe50"
      k.to_s(2).size.should eq 160
    end

    it "should calculate x" do
      x = SRP.calc_x(username, password, salt)
      x.to_s(16).should eq "bdd0a4e1c9df4082684d8d358b8016301b025375"
      x.to_s(2).size.should eq 160
    end

    it "should calculate verifier" do
      x = SRP.to_big_int "bdd0a4e1c9df4082684d8d358b8016301b025375"
      v = SRP.calc_v(x, n, g)
      v.to_s(16).should eq "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309"
      v.to_s(2).size.should eq 256
    end

    it "should calculate u" do
      aa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      bb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      u = SRP.calc_u(aa, bb, n)
      u.to_s(16).should eq "c60b17ddf568dd5743d0e3ba5621646b742432c5"
      u.to_s(2).size.should eq 160
    end

    it "should calculate public client value A" do
      aa = SRP.calc_a(a, n, g)
      aa.to_s(16).should eq "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      aa.to_s(2).size.should eq 256
    end

    it "should calculate public server value B" do
      k = SRP.to_big_int "dbe5dfe0704fee4c85ff106ecd38117d33bcfe50"
      v = SRP.to_big_int "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309"
      bb = SRP.calc_b(b, k, v, n, g)
      bb.to_s(16).should eq "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      bb.to_s(2).size.should eq 256
    end

    it "should calculate session key from client params" do
      bb = SRP.to_big_int "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      k = SRP.to_big_int "dbe5dfe0704fee4c85ff106ecd38117d33bcfe50"
      x = SRP.to_big_int "bdd0a4e1c9df4082684d8d358b8016301b025375"
      u = SRP.to_big_int "c60b17ddf568dd5743d0e3ba5621646b742432c5"
      ss = SRP.calc_client_s(bb, a, k, x, u, n, g)
      ss.to_s(16).should eq "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
      ss.to_s(2).size.should eq 256
    end

    it "should calculate session key from server params" do
      aa = SRP.to_big_int "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      v = SRP.to_big_int "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309"
      u = SRP.to_big_int "c60b17ddf568dd5743d0e3ba5621646b742432c5"
      ss = SRP.calc_server_s(aa, b, v, u, n)
      ss.to_s(16).should eq "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
      ss.to_s(2).size.should eq 256
    end

    it "should calculate M" do
      xaa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      xbb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      xss = "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
      xkk = SRP.sha1_hex(xss)
      xkk.should eq "5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67"
      mm = SRP.calc_m(username, salt, xaa, xbb, xkk, n, g)
      mm.to_s(16).should eq "2da30b225850c17720ed483ae6d04bcb67e4448e"
    end

    it "should calculate H(AMK)" do
      xaa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      xmm = "d597503056af882d5b27b419302ac7b2ea9d7468"
      xkk = "5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67"
      h_amk = SRP.calc_h_amk(xaa, xmm, xkk, n, g)
      h_amk.to_s(16).should eq "ffc955a9227f1bf1d87d66bebecba081f54dbb7a"
    end
  end
end
