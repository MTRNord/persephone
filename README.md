[![DeepSource](https://app.deepsource.com/gh/MTRNord/persephone.svg/?label=active+issues&show_trend=true&token=ySiOHgM0IAnpEO5N3mWVcmVg)](https://app.deepsource.com/gh/MTRNord/persephone/)

# Persephone

Persephone is an experimental and WIP matrix homeserver written in C++20.

## Goals

- Support specifically a server size of 25-1k users with 30-40 normal usage rooms per user.
    - This does not mean we will cripple performance if it's better than this.
- Allow upscaling easily
- Don't expose too many switches to the user via the config
    - One should be able to understand the whole config fully in less than 2 normal evenings.
    - One should not need more than home-admin understandings of concepts.
- There should be tests from the start
    - Unit tests
    - Benchmarks
    - Fuzzing

## Technology

The technology used will be:

- C++20
- Postgresql
- [drogon](https://drogon.org/)
- snitch2
- ldns

## Building

TODO. Bulk of it: Install ninja, meson and cmake and install drogon.
