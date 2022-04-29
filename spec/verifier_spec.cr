require "./spec_helper"

module SecureRemotePassword
  # ## Test predefined values for N and g.
  # ## Values are from vectors listed in RFC 5054 Appendix B.
  describe Verifier do
    it "should be 1024 bits" do
      srp = Verifier.new(1024)
      nn = srp.n
      nn.to_s(16).should eq "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3"
      nn.to_s(2).size.should eq 1024
      srp.g.should eq 2
    end

    it "should be 1536 bits" do
      srp = Verifier.new(1536)
      nn = srp.n
      nn.to_s(2).size.should eq 1536
      srp.g.should eq 2
    end

    it "should be 2048 bits" do
      srp = Verifier.new(2048)
      nn = srp.n
      nn.to_s(2).size.should eq 2048
      srp.g.should eq 2
    end

    it "should be 3072 bits" do
      srp = Verifier.new(3072)
      nn = srp.n
      nn.to_s(2).size.should eq 3072
      srp.g.should eq 5
    end

    it "should be 4096 bits" do
      srp = Verifier.new(4096)
      nn = srp.n
      nn.to_s(2).size.should eq 4096
      srp.g.should eq 5
    end

    it "should be 6144 bits" do
      srp = Verifier.new(6144)
      nn = srp.n
      nn.to_s(2).size.should eq 6144
      srp.g.should eq 5
    end

    it "should be 8192 bits" do
      srp = Verifier.new(8192)
      nn = srp.n
      nn.to_s(2).size.should eq 8192
      srp.g.should eq 19
    end

    # ## Test server-side Verifier.
    # ## Values are from http://srp.stanford.edu/demo/demo.html
    # ## using 1024 bit values.
    username = "user"
    password = "password"
    salt = "16ccfa081895fe1ed0bb"
    _a = "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2"
    b = "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96"

    it "should calculate k" do
      k = Verifier.new(1024).k
      k.should eq SRP.to_big_int("7556aa045aef2cdd07abaf0f665c3e818913186f")
    end

    it "should generate salt and verifier" do
      auth = Verifier.new(1024).generate_userauth(username, password)
      auth[:username].should eq username
      auth[:verifier].should be_truthy
      auth[:salt].should be_truthy
    end

    it "should calculate verifier with given salt" do
      srp = Verifier.new(1024)
      srp.set_salt salt
      auth = srp.generate_userauth(username, password)
      v = auth[:verifier]
      auth[:salt].should eq salt
      v.should eq "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
    end

    it "should generate salt and calculate verifier" do
      srp = Verifier.new(1024)
      auth = srp.generate_userauth(username, password)
      v = SRP.to_big_int auth[:verifier]
      asalt = SRP.to_big_int auth[:salt]
      v.to_s(2).size.should be >= 1000
      asalt.to_s(2).size.should be >= 50
    end

    it "should generate B with predefined b" do
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
      srp = Verifier.new(1024)
      srp.set_b SRP.to_big_int b
      bb = srp.generate_b(v)
      bb.should eq "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
    end

    it "should generate B" do
      srp = Verifier.new(1024)
      bb = SRP.to_big_int srp.generate_b("0")
      bb.to_s(2).size.should be >= 1000
      srp.b.to_s(2).size.should be > 200
    end

    it "should calculate server session and key" do
      # A is received in phase 1
      aa = "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
      # B and b are saved from phase 1
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      # v is from db
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
      _proof = {:A => aa, :B => bb, :b => b,
                :I => username, :s => salt, :v => v}
      srp = Verifier.new(1024)
      srp.verify_session(_proof, "match insignificant")
      srp.s.should eq "7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314"
      srp.big_k.should eq "404bf923682abeeb3c8c9164d2cdb6b6ba21b64d"
    end

    it "should calculate verifier M and server proof" do
      # A is received in phase 1
      aa = "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
      # B and b are saved from phase 1
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      # v is from db
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
      # S is validated
      ss = "7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314"
      # K = H(S)
      SRP.sha1_hex(ss)
      client_m = "52fb39fcacc2d909675ea3cf2b967980fc40ae0"
      _proof = {:A => aa, :B => bb, :b => b,
                :I => username, :s => salt, :v => v}
      srp = Verifier.new(1024)
      srp.verify_session(_proof, client_m)
      srp.m.should eq client_m
      srp.h_amk.should eq "d3668cebb1cba4b3d4a4cd8edde9d89279b9d1e9"
    end
  end
end
