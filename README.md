# Secure Remote Password for Crystal Lang

[![CI](https://github.com/spider-gazelle/secure-remote-password/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/secure-remote-password/actions/workflows/ci.yml)

This is a pure Crystal implementation of the Secure Remote Password protocol (SRP-6a).

SRP is an authentication method that allows the use of user names and passwords over an insecure network connection without revealing the password. If the client side lacks the user's password or the server side lacks the proper verification key, the authentication will fail.

Unlike other common challenge-response autentication protocols, such as Kerberos and SSL, SRP does not rely on an external infrastructure of trusted key servers or certificate management.

## HomeKit Accessory Protocol Specification (HAP)

HomeKit authentication is supported when using SHA-512, these changes are made to the SRP protocol:

- SHA-512 is used as the hash function, replacing SHA-1
- The Modulus, N, and Generator, g, are specified by the 3072-bit group of [RFC 5054](https://tools.ietf.org/html/rfc5054)
- The match, M, hash calculation is not padded

These changes improve security and are used as defaults

## References

- [RFC 2945](https://tools.ietf.org/html/rfc2945)
- [RFC 5054](https://tools.ietf.org/html/rfc5054)
- [Homekit accessory protocol specification (non-commercial version)](https://developer.apple.com/documentation/homekit)
-	[http://srp.stanford.edu/](http://srp.stanford.edu/)
-	[http://srp.stanford.edu/demo/demo.html](http://srp.stanford.edu/demo/demo.html)

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

# The username, verifier and salt should be stored in the server database
server_verifier = SecureRemotePassword::Verifier.new
auth = verifier.generate_user_verifier(username, password)
auth # => {username: username, verifier: ..., salt: ...}

# ~~~ Begin Authentication ~~~

client = SecureRemotePassword::Client.new(username, password)
client_a = client.start_authentication

# Send username and client_a to the server
# Client => Server: username, client_a

# Server retrieves user's verifier and salt from the database.
# auth = lookup_user(username)
salt = auth[:salt]
verifier = auth[:verifier]

# Server generates challenge for the client.
challenge, proof = server_verifier.get_challenge_and_proof(username, verifier, salt, client_a)

# Server sends the challenge containing salt and proof (B) to client.
# Server => Client: challenge.salt, challenge.proof (B)

# Client calculates match (M) as a response to the challenge.
client_m = client.process_challenge(challenge)

# Client => Server: username, client_m

# Verify challenge response M.
# The Verifier state is passed in proof (server should persist this during negotiation)
server_h_amk = verifier.verify_session(proof, client_m)
# is nil if authentication failed.


# At this point, the client and server should have a common session key
# that is secure (i.e. not known to an outside party).  To finish
# authentication, they must prove to each other that their keys are
# identical.


# server to send server_h_amk to the client
# Server => Client: server_h_amk

client.verify(server_h_amk) == true

```

## Credit

The original SRP-6a work was done by [lamikae](https://github.com/lamikae/) in the [srp-rb](https://github.com/lamikae/srp-rb) project.
The HomeKit implementation by [karlentwistle](https://github.com/karlentwistle/ruby_home-srp/)
