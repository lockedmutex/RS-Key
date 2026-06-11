# Motivation

<!-- TODO(owner): personal motivation text goes here. -->

Until the long version lands, the short one:

Commercial security keys are excellent — and closed. Their firmware is a
black box, their capacity limits are product-segmentation choices, and when
a key dies or a vendor discontinues a line, your enrolled identity dies with
it.

RS-Key exists to see how far an open, auditable, memory-safe implementation
on commodity silicon can get: every byte of firmware readable, every parser
fuzzed, the at-rest story rooted in fuses you burned yourself, and a backup
mechanism that treats *your* identity as yours — while staying drop-in
compatible with the tooling people actually use.

It is also, frankly, a love letter to writing real systems software in Rust
on a $10 board.
