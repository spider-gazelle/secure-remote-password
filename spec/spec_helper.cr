require "spec"
require "../src/secure-remote-password"

class SecureRemotePassword::Client
  def custom_group(@arg_N, @arg_g)
    @arg_k = calculate_k
  end
end
