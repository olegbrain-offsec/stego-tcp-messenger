# Steganography tool: TCP + Pseudorandom bytes injection + TLS as upper chipher
This tool aims to help with communication in unreliable areas. This program is a simple proof-of-concept for random data bytes injection.

## Features
1. TLS as outter data protection;
2. The data packet contains random bytes mixed with data bytes according to the pseudorandom sequence generation algorithm (seed-based).

## TODO
1. Restoring session with skipping some iterations if data is unreadable
2. Saving secret key in safe manner
