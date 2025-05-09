# README

This repository is part of my master thesis.
I needed to analyze the SSRF vulnerabilities in [WebGoat](https://github.com/WebGoat/WebGoat).

This repo contains only the specifications for [secucheck](https://github.com/secure-software-engineering/secucheck).
We used branch `SC-1.2.0`.

The configuration file for secucheck is [secucheck.yml](/secucheck.yml).
Adjust it for your system.

## Note

The vulnerabilities in WebGoat are sometimes "artificial" (see task 1).
In this case, we needed to define non-sinks as sinks in order to identify the vulnerabilities.
However, this leads to false-positives.
This should not be the case for a real-world application.
