require "./spec_helper"

module SecureRemotePassword
  # ## Test Client.
  # ## Values are from http://srp.stanford.edu/demo/demo.html
  # ## using 1024 bit values.
  describe Client do
    username = "user"
    password = "password"
    salt = "16ccfa081895fe1ed0bb"
    a = "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2"
    _b = "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96"

    it "should generate A from random a" do
      srp = Client.new(1024, :sha1)
      aa1 = SRP.to_big_int srp.start_authentication
      aa1.to_s(2).size.should be >= 1000
      srp = Client.new(1024, :sha1)
      aa2 = SRP.to_big_int srp.start_authentication
      aa2.to_s(2).size.should be >= 1000
      aa1.should_not eq aa2
    end

    it "should calculate A" do
      srp = Client.new(1024, :sha1)
      srp.set_a SRP.to_big_int(a)
      aa = srp.start_authentication
      aa.should eq "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
    end

    it "should calculate client session and key" do
      srp = Client.new(1024, :sha1)
      srp.set_a SRP.to_big_int(a)
      srp.start_authentication # created in phase 1
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      srp.process_challenge(username, password, salt, bb)
      srp.s.should eq "7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314"
      srp.big_k.should eq "404bf923682abeeb3c8c9164d2cdb6b6ba21b64d"
    end
  end

  # ## Simulate actual authentication scenario over HTTP
  # ## when the server is RESTful and has to persist authentication
  # ## state between challenge and response.
  context "authentication" do
    username = "leonardo"
    password = "icnivad"
    auth = Verifier.new(1024, :sha1).generate_userauth(username, password)
    # imitate database persistance layer
    _user_name = username
    _user = {
      verifier: auth[:verifier],
      salt:     auth[:salt],
    }

    it "should authenticate" do
      client = Client.new(1024, :sha1)
      verifier = Verifier.new(1024, :sha1)
      # phase 1
      # (client)
      aa = client.start_authentication
      # (server)
      v = auth[:verifier]
      salt = auth[:salt]
      bb = verifier.generate_b v
      b = verifier.b.to_s(16)
      # phase 2
      # (client)
      client_m = client.process_challenge(username, "icnivad", salt, bb).not_nil!
      # (server)
      _proof = {A: aa, B: bb, b: b, I: username, s: salt, v: v}
      server_h_amk = verifier.verify_session(_proof, client_m)
      server_h_amk.should be_truthy
      # (client)
      client.h_amk.should eq server_h_amk
    end

    it "should not authenticate" do
      client = Client.new(1024, :sha1)
      verifier = Verifier.new(1024, :sha1)
      # phase 1
      # (client)
      aa = client.start_authentication
      # (server)
      v = auth[:verifier]
      salt = auth[:salt]
      bb = verifier.generate_b v
      b = "%x" % verifier.b
      # phase 2
      # (client)
      client_m = client.process_challenge(username, "wrong password", salt, bb).not_nil!
      # (server)
      _proof = {A: aa, B: bb, b: b, I: username, s: salt, v: v}
      verifier.verify_session(_proof, client_m).should be_nil
      verifier.h_amk.should_not be_truthy
    end

    it "should be applied in async authentication with stateless server" do
      # client generates A and begins authentication process
      client = Client.new(1024, :sha1)
      aa = client.start_authentication

      #
      # username and A are received  (client --> server)
      #

      # server finds user from "database"
      _user.should_not be_nil
      v = _user[:verifier]
      salt = _user[:salt]

      # server generates B, saves A and B to database
      srp = Verifier.new(1024, :sha1)
      _session = srp.get_challenge_and_proof(username, v, salt, aa).not_nil!
      _session[:challenge][:B].should eq srp.big_b
      _session[:challenge][:salt].should eq salt
      # store proof to memory
      _user_session_proof = _session[:proof]

      # server sends salt and B
      client_response = _session[:challenge]

      #
      # client receives B and salt  (server --> client)
      #
      bb = client_response[:B]
      salt = client_response[:salt]
      # client generates session key
      # at this point _client_srp.a should be persisted!! calculate_client_key is stateful!
      mmc = client.process_challenge username, "icnivad", salt, bb
      client.a.should be_truthy
      client.m.should eq mmc
      client.big_k.should be_truthy
      client.h_amk.should be_truthy
      # client sends M --> server
      client_m = client.m

      #
      # server receives client session key  (client --> server)
      #

      # retrive session from database
      srp = Verifier.new(1024, :sha1)
      verification = srp.verify_session(_user_session_proof, client_m)
      verification.should_not be_nil

      # Now the two parties have a shared, strong session key K.
      # To complete authentication, they need to prove to each other that their keys match.
      client.verify(verification).should eq true
      verification.should eq client.h_amk
    end
  end
end
