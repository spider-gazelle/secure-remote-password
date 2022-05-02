module SecureRemotePassword
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  enum Algorithm
    SHA1
    SHA512
  end
end

require "./secure-remote-password/*"
