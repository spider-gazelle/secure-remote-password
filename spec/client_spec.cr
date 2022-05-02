require "./spec_helper"

module SecureRemotePassword
  describe Client do
    username = "user"
    password = "password"
    salt = "16ccfa081895fe1ed0bb"

    a = "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2".to_big_i(16)
    b = "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96".to_big_i(16)
    client = Client.new(username, password, 1024, :sha1, a)
    client.custom_group "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3".to_big_i(16), BigInt.new(2)

    it "should calculate k" do
      client.arg_k.to_s(16).should eq "dbe5dfe0704fee4c85ff106ecd38117d33bcfe50"
    end

    it "should calculate x" do
      x = client.calculate_x(salt)
      x.to_s(16).should eq "bdd0a4e1c9df4082684d8d358b8016301b025375"
    end

    it "should calculate verifier" do
      client.calculate_v(salt).to_s(16).should eq "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309"
    end

    it "should calculate u" do
      aa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      bb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      u = client.calculate_u(aa, bb)
      u.to_s(16).should eq "c60b17ddf568dd5743d0e3ba5621646b742432c5"
    end

    it "should calculate public client value A" do
      aa = client.calculate_A(a)
      aa.to_s(16).should eq "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
    end

    it "should calculate public server value B" do
      v = "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309".to_big_i(16)
      bb = client.calculate_B(b, v)
      bb.to_s(16).should eq "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
    end

    it "should calculate session key from client params" do
      bb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68".to_big_i(16)
      u = "c60b17ddf568dd5743d0e3ba5621646b742432c5".to_big_i(16)
      ss = client.calculate_client_S(bb, salt, u, a)
      ss.to_s(16).should eq "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
    end

    it "should calculate M" do
      xaa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      xbb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      xss = "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
      xkk = client.hash_hex(xss)
      xkk.should eq "5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67"
      mm = client.calculate_M(username, salt, xaa, xbb, xkk)
      mm.to_s(16).should eq "f2c0762cd5fdad595689241e3beb9b7178faf33d"
    end

    it "should calculate H(AMK)" do
      xaa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      xmm = "d597503056af882d5b27b419302ac7b2ea9d7468"
      xkk = "5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67"
      h_amk = client.calculate_h_amk(xaa, xmm, xkk)
      h_amk.to_s(16).should eq "ffc955a9227f1bf1d87d66bebecba081f54dbb7a"
    end
  end

  describe "authentication" do
    username = "leonardo"
    password = "icnivad"
    verifier = Verifier.new(1024, :sha1)

    # This is our test user database
    auth = verifier.generate_user_verifier(username, password)

    it "should authenticate" do
      client = Client.new(username, password, 1024, :sha1)
      # phase 1
      # (client)
      client_A = client.start_authentication
      # (server)
      challenge, proof = verifier.get_challenge_and_proof(username, auth[:verifier], auth[:salt], client_A)

      # phase 2
      # (client)
      client_m = client.process_challenge(challenge)
      # (server)
      server_h_amk = verifier.verify_session(proof, client_m)
      server_h_amk.should be_truthy
      # (client)
      client.verify(server_h_amk).should be_true
    end

    it "should not authenticate" do
      client = Client.new(username, "wrongpass", 1024, :sha1)

      # phase 1
      # (client)
      client_A = client.start_authentication
      # (server)
      challenge, proof = verifier.get_challenge_and_proof(username, auth[:verifier], auth[:salt], client_A)

      # phase 2
      # (client)
      client_m = client.process_challenge(challenge)
      # (server)
      server_h_amk = verifier.verify_session(proof, client_m)
      server_h_amk.should be_nil
      # (client)
      client.verify(server_h_amk).should be_false
    end

    it "should be applied in async authentication with stateless server" do
      # client generates A and begins authentication process
      client = Client.new(username, password, 1024, :sha1)
      aa = client.start_authentication

      #
      # username and A are received  (client --> server)
      #

      # server finds user from "database"
      v = auth[:verifier]
      salt = auth[:salt]

      # server generates B, saves A and B to database
      srp = Verifier.new(1024, :sha1)
      challenge, proof = srp.get_challenge_and_proof(username, v, salt, aa)
      challenge.proof.should eq proof.arg_B
      challenge.salt.should eq proof.salt

      #
      # client receives B and salt  (server --> client)
      #
      # client generates session key
      # at this point _client_srp.a should be persisted!! calculate_client_key is stateful!
      client_m = client.process_challenge challenge

      # client sends M --> server

      #
      # server receives client session key  (client --> server)
      #

      # retrive session from database
      srp = Verifier.new(1024, :sha1)
      verification = srp.verify_session(proof, client_m)
      verification.should_not be_nil

      # Now the two parties have a shared, strong session key K.
      # To complete authentication, they need to prove to each other that their keys match.
      client.verify(verification).should eq true
    end
  end
end
