# CBOR Encoded Message Syntax - C# class library

This directory contains a stand alone class library for the COSE specification.

In order to compile this project, the following additional projects are needed.:

CBOR - We use the project @ https://github.com/peteroupc/CBOR for this purpose.
Crypto - We use the Bouncy Castle C# library for this purpose.

## Current State

It can do encoding for a lot of things, but doesn't yet do any decoding to speak of.

## Contributing

Fill in what the rules are - however it should be something along the lines of - all contributions are run under the GPL or MIT license

## Available versions

The initial version that is provided is wrtten in c#.  It is hoped that a JavaScript version wil appear as well.

##  Test Vectors

The intention is to provide a set of test vectors that will and will not decode correctly for to allow implemetations to test themselves.  Each of the provided implemetions will provide a test program which checks against the test vectors.

