# Secure Remote Password for Crystal Lang

This is a pure Ruby implementation of the Secure Remote Password protocol (SRP-6a).

SRP is an authentication method that allows the use of user names and passwords over an insecure network connection without revealing the password. If the client side lacks the user's password or the server side lacks the proper verification key, the authentication will fail.

Unlike other common challenge-response autentication protocols, such as Kerberos and SSL, SRP does not rely on an external infrastructure of trusted key servers or certificate management.


References

*	[http://srp.stanford.edu/](http://srp.stanford.edu/)
*	[http://srp.stanford.edu/demo/demo.html](http://srp.stanford.edu/demo/demo.html)


## HomeKit Accessory Protocol Specification (HAP)

Additional classes for handling HomeKit are included, these changes are made to the SRP protocol:

- SHA-512 is used as the hash function, replacing SHA-1
- The Modulus, N, and Generator, g, are specified by the 3072-bit group of [RFC 5054](https://tools.ietf.org/html/rfc5054)

## References

- [RFC 2945](https://tools.ietf.org/html/rfc2945)
- [RFC 5054](https://tools.ietf.org/html/rfc5054)
- [Homekit accessory protocol specification (non-commercial version)](https://developer.apple.com/documentation/homekit)

## Installation

Add the dependency to your `shard.yml`:

  ```yaml
    dependencies:
      secure-remote-password:
        github: spider-gazelle/secure-remote-password
  ```

## Usage

```crystal
require 'secure-remote-password'

username = "user"
password = "password"
prime_length = 1024


# The salt and verifier should be stored on the server database.

@auth = SecureRemotePassword::Verifier.new(prime_length).generate_userauth(username, password)
# @auth is a hash containing :username, :verifier and :salt


# ~~~ Begin Authentication ~~~

client = SecureRemotePassword::Client.new(prime_length)
client_a = client.start_authentication()


# Client => Server: username, A

# Server retrieves user's verifier and salt from the database.
v = @auth[:verifier]
salt = @auth[:salt]

# Server generates challenge for the client.
verifier = SecureRemotePassword::Verifier.new(prime_length)
session = verifier.get_challenge_and_proof(username, v, salt, client_a)

# Server sends the challenge containing salt and B to client.
response = session[:challenge]

# Server has to persist proof to authenticate the client response.
@proof = session[:proof]


# Server => Client: salt, B (proof)

# Client calculates M as a response to the challenge.
client_m = client.process_challenge(username, password, salt, @proof[:B])


# Client => Server: username, client_m

# New verifier may be instantiated on the server.
verifier = SecureRemotePassword::Verifier.new(prime_length)

# Verify challenge response M.
# The Verifier state is passed in @proof.
server_h_amk = verifier.verify_session(@proof, client_m)
# Is nil if authentication failed.


# At this point, the client and server should have a common session key
# that is secure (i.e. not known to an outside party).  To finish
# authentication, they must prove to each other that their keys are
# identical.


# Server => Client: H(AMK)

client.verify(server_h_amk) == true

```

## Credit

The original SRP-6a work was done by [lamikae](https://github.com/lamikae/) in the [srp-rb](https://github.com/lamikae/srp-rb) project.
The HomeKit implementation by [karlentwistle](https://github.com/karlentwistle/ruby_home-srp/)
