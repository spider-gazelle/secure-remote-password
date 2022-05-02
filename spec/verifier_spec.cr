require "./spec_helper"

module SecureRemotePassword
  # ## Test predefined values for N and g.
  # ## Values are from vectors listed in RFC 5054 Appendix B.
  describe Verifier do
    it "should be 1024 bits" do
      srp = Verifier.new(1024, :sha1)
      nn = srp.arg_N
      nn.to_s(16).should eq "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3"
      nn.to_s(2).size.should eq 1024
      srp.arg_g.should eq 2
    end

    it "should be 1536 bits" do
      srp = Verifier.new(1536, :sha1)
      nn = srp.arg_N
      nn.to_s(2).size.should eq 1536
      srp.arg_g.should eq 2
    end

    it "should be 2048 bits" do
      srp = Verifier.new(2048, :sha1)
      nn = srp.arg_N
      nn.to_s(2).size.should eq 2048
      srp.arg_g.should eq 2
    end

    it "should be 3072 bits" do
      srp = Verifier.new(3072, :sha1)
      nn = srp.arg_N
      nn.to_s(2).size.should eq 3072
      srp.arg_g.should eq 5
    end

    it "should be 4096 bits" do
      srp = Verifier.new(4096, :sha1)
      nn = srp.arg_N
      nn.to_s(2).size.should eq 4096
      srp.arg_g.should eq 5
    end

    it "should be 6144 bits" do
      srp = Verifier.new(6144, :sha1)
      nn = srp.arg_N
      nn.to_s(2).size.should eq 6144
      srp.arg_g.should eq 5
    end

    it "should be 8192 bits" do
      srp = Verifier.new(8192, :sha1)
      nn = srp.arg_N
      nn.to_s(2).size.should eq 8192
      srp.arg_g.should eq 19
    end

    # ## Test server-side Verifier.
    # ## Values are from http://srp.stanford.edu/demo/demo.html
    # ## using 1024 bit values.
    username = "user"
    password = "password"
    salt = "16ccfa081895fe1ed0bb"
    b = "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96"

    it "should calculate k" do
      k = Verifier.new(1024, :sha1).arg_k
      k.should eq "7556aa045aef2cdd07abaf0f665c3e818913186f".to_big_i(16)
    end

    it "should generate salt and verifier" do
      auth = Verifier.new(1024).generate_user_verifier(username, password)
      auth[:username].should eq username
      auth[:verifier].should be_truthy
      auth[:salt].should be_truthy
    end

    it "should calculate verifier with given salt" do
      srp = Verifier.new(1024, :sha1)
      auth = srp.generate_user_verifier(username, password, salt)
      auth[:salt].should eq salt
      auth[:verifier].should eq "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
    end

    it "should generate B with predefined b" do
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
      srp = Verifier.new(1024, :sha1)
      bb = srp.calculate_B(b.to_big_i(16), v.to_big_i(16)).to_s(16)
      bb.should eq "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
    end

    it "should calculate verifier M and server proof" do
      # A is received in phase 1
      aa = "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
      # B and b are saved from phase 1
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      # v is from db
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"

      client_m = "52fb39fcacc2d909675ea3cf2b967980fc40ae0"
      proof = Proof.new(
        client_A: aa,
        arg_B: bb,
        arg_b: b,
        username: username,
        salt: salt,
        verifier: v
      )
      srp = Verifier.new(1024, :sha1)
      h_amk = srp.verify_session(proof, client_m)
      h_amk.should eq "d3668cebb1cba4b3d4a4cd8edde9d89279b9d1e9"
    end
  end
end
