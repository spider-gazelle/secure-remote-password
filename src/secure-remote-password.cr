module SecureRemotePassword
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}
end

require "./secure-remote-password/*"
