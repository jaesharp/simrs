# simrs-jcop-profile

JCOP variant profile definitions per the IBM JCOP Family datasheet.

Each JCOP card model maps to a `JcopProfile` specifying its hardware
capabilities: EEPROM size, RAM budget, SCP version, crypto algorithms,
and interface support (contact/contactless). Covers JCOP10 through
JCOP31bio.

`no_std`. Pure data definitions, no dependencies.
