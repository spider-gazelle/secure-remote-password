require "./spec_helper"

module SecureRemotePassword
  describe Helpers do
    username = "alice"
    password = "password123"
    salt = "BEB25379D1A8581EB5A727673A2441EE"
    a = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393".to_big_i(16)
    b = "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20".to_big_i(16)

    client = Client.new(username, password, 1024, :sha1, a)

    # pre-calculate the client values
    v = client.calculate_v(salt)
    bb = client.calculate_B(b, v)
    aa = client.calculate_A(a)
    u = client.calculate_u(aa, bb)
    s = client.calculate_client_S(bb, salt, u, a)
    kk = client.hash_hex(s.to_s(16))
    mm = client.calculate_M(username, salt, aa, bb, kk)

    # Server side
    ss = client.calculate_server_S(aa, v, u, bb)

    it "should calculate k" do
      client.arg_k.to_s(16, upcase: true).should eq "7556AA045AEF2CDD07ABAF0F665C3E818913186F"
    end

    it "should calculate x" do
      client.calculate_x(salt).to_s(16, upcase: true).should eq "94B7555AABE9127CC58CCF4993DB6CF84D16C124"
    end

    it "should calculate verifier" do
      client.calculate_v(salt).to_s(16, upcase: true).should eq "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB"
    end

    it "should calculate public client value A" do
      aa.to_s(16, upcase: true).should eq "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B"
    end

    it "should calculate public server value B" do
      bb.to_s(16, upcase: true).should eq "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58"
    end

    it "should be able to calculate u" do
      u.to_s(16, upcase: true).should eq "CE38B9593487DA98554ED47D70A7AE5F462EF019"
    end

    it "should be able to calculate the client premaster secret" do
      s.to_s(16, upcase: true).should eq "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"
    end

    it "should be able to calculate M" do
      mm.to_s(16, upcase: true).should eq "E5F39493B07B8B88E2A4F44BC9282874CD2DEBED"
    end

    it "should be able to calculate the server premaster secret" do
      ss.to_s(16, upcase: true).should eq "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"
    end

    it "should match the server's premaster secret" do
      s.should eq ss
    end
  end

  describe Client do
    username = "user"
    password = "password"
    salt = "16ccfa081895fe1ed0bb"

    a = "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2".to_big_i(16)
    client = Client.new(username, password, 1024, :sha1, a)

    it "should calculate A" do
      aa = client.start_authentication
      aa.should eq("165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2")
    end

    it "should calculate client session and key" do
      client.start_authentication
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      client.process_challenge(Challenge.new(bb, salt))
      client.session_key.should eq("7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314")
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
  end
end
