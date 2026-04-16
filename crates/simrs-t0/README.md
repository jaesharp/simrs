# simrs-t0

ISO 7816-3 T=0 character protocol and ATR handling.

Implements the character-level transport layer between a terminal and a
smart card. The T=0 state machine converts between byte-at-a-time I/O
and complete APDU commands/responses. Also handles ATR (Answer To Reset)
parsing and PPS (Protocol and Parameters Selection) exchange.

`no_std`, no alloc.
