# features/jcvm_security.feature
#
# Security regression tests for JavaCard Virtual Machine (JCVM) based on
# known bytecode-level attacks from the academic literature.
#
# These scenarios define the contract that a conforming JCVM implementation
# must satisfy to defend against demonstrated attack classes. All scenarios
# These scenarios define the security contract that the simrs JCVM
# implementation must satisfy to defend against demonstrated attack classes.
#
# Standards:
#   Java Card Virtual Machine Specification 3.1  Chapter 3 (Runtime Data Areas)
#   Java Card Virtual Machine Specification 3.1  Chapter 6 (CAP File Loading)
#   Java Card Runtime Environment Specification 2.2.1  Chapter 6 (Applet Firewall)
#   Java Card Runtime Environment Specification 2.2.1  Chapter 7 (Transactions)
#
# Attack references:
#   Witteman, "Java Card Security," ISB 8 (2003)
#   Poll & Mostowski, "Malicious Code on Java Card Smartcards," CARDIS 2008
#   Bouffard, Iguchi-Cartigny & Lanet, "Combined Software and Hardware
#     Attacks on the Java Card Control Flow," CARDIS 2011
#   Barbu, Hoogvorst & Duc, "Tampering with Java Card Exceptions,"
#     SECRYPT 2012
#   Lancia & Bouffard, "Java Card Virtual Machine Compromising from a
#     Bytecode Verified Applet," CARDIS 2015
#   Dubreuil & Bouffard, "PhiAttack: Rewriting the Java Card Class
#     Hierarchy," CARDIS 2021

Feature: JCVM Security Regressions (CARDIS 2003-2021 Attack Defenses)
  As a JavaCard Virtual Machine implementation
  I must enforce runtime type safety, applet firewall isolation, transaction
  atomicity for security-critical state, CAP file structural integrity, and
  exception handler bounds validation to defend against the seven families
  of bytecode-level attacks demonstrated against real hardware.

  # ---------------------------------------------------------------------------
  # Defense: Transaction abort must not roll back PIN try counter
  #
  # Witteman (2003) / Hubbers, Mostowski & Poll, eSmart 2006:
  # The transaction mechanism rolls back EEPROM field updates on abort.
  # If the PIN try counter is stored as a persistent field and updated
  # inside a transaction, aborting the transaction rolls back the counter
  # decrement -- giving the attacker unlimited PIN guesses.
  #
  # JCRE 2.2.1 clause 7.7: "The PIN try counter update resulting from an
  # unsuccessful PIN verification shall not be rolled back by
  # abortTransaction()."
  # ---------------------------------------------------------------------------

  Scenario: Transaction abort does not roll back PIN try counter
    # Witteman 2003; JCRE 2.2.1 clause 7.7
    # Attack: beginTransaction(), PIN.check(wrong_pin), abortTransaction().
    # If the try counter rolls back, the attacker can retry indefinitely.
    Given applet A is installed with a PIN [31 32 33 34] and max tries 3
    And applet A is selected
    And the PIN try counter is at its maximum value of 3
    When applet A calls beginTransaction()
    And applet A calls PIN.check() with incorrect PIN [00 00 00 00]
    Then the PIN try counter is decremented to 2
    When applet A calls abortTransaction()
    Then the PIN try counter remains at 2
    And the PIN try counter was NOT rolled back to 3

  # ---------------------------------------------------------------------------
  # Defense: Applet firewall context isolation
  #
  # Poll & Mostowski, CARDIS 2008, Section 3:
  # The applet firewall must prevent any applet from reading or writing
  # another applet's instance fields, even if the attacker has a reference
  # to the target object (obtained via type confusion or CAP manipulation).
  #
  # JCRE 2.2.1 Chapter 6: "An applet instance shall only access objects
  # owned by its own context. Access to objects owned by another context
  # shall throw SecurityException."
  # ---------------------------------------------------------------------------

  Scenario: Firewall prevents cross-applet instance field access
    # Poll & Mostowski, CARDIS 2008, Section 3; JCRE 2.2.1 Chapter 6
    # Applet A attempts to read applet B's instance field via a crafted
    # getfield bytecode. The JCVM must check object ownership at runtime
    # and throw SecurityException.
    Given applet A is installed in context A with AID [A0 00 00 00 62 01 01]
    And applet B is installed in context B with AID [A0 00 00 00 62 02 01]
    And applet B has an instance field secretKey of type byte[]
    When applet A attempts getfield on applet B's secretKey reference
    Then the JCVM throws SecurityException
    And applet A receives no data from applet B's fields

  # ---------------------------------------------------------------------------
  # Defense: Array bounds enforcement (no adjacent memory leak)
  #
  # Poll et al., CARDIS 2008, Section 4.1-4.3:
  # baload/saload with an index >= array.length must throw
  # ArrayIndexOutOfBoundsException. If the bounds check is missing or
  # bypassed, the attacker reads memory adjacent to the array -- potentially
  # other applets' data, JCVM metadata, or cryptographic keys.
  #
  # JCVM 3.1 Section 3.11.3: "Each array access instruction shall verify
  # at runtime that the index is within [0, array.length - 1]."
  # ---------------------------------------------------------------------------

  Scenario: Array bounds enforcement prevents adjacent memory read
    # Poll et al., CARDIS 2008, Section 4; JCVM 3.1 Section 3.11.3
    Given applet A has a byte array of length 8
    When applet A executes baload with index 8 (equal to array.length)
    Then the JCVM throws ArrayIndexOutOfBoundsException
    And no data from adjacent memory is returned
    When applet A executes baload with index 255
    Then the JCVM throws ArrayIndexOutOfBoundsException
    When applet A executes saload with index -1 (0xFFFF as unsigned short)
    Then the JCVM throws ArrayIndexOutOfBoundsException

  # ---------------------------------------------------------------------------
  # Defense: Type confusion prevention (byte[] vs short[] array mismatch)
  #
  # Poll et al., CARDIS 2008; Bouffard et al., CARDIS 2011:
  # A byte[] reference must not be usable as a short[] reference. If the
  # runtime allows this, the attacker reads 2 bytes per index position
  # instead of 1, doubling the accessible memory range from a single array.
  #
  # JCVM 3.1 Section 3.11.3: "saload shall verify that the reference refers
  # to an array of type short[]. A type mismatch shall throw
  # ArrayStoreException."
  # ---------------------------------------------------------------------------

  Scenario: Type confusion between byte[] and short[] arrays is prevented
    # Poll et al., CARDIS 2008, Section 4.1; JCVM 3.1 Section 3.11.3
    # Attack: via CAP manipulation, change baload (0x33) to saload (0x35)
    # on a byte[] reference. The runtime must check the array's type tag.
    Given applet A has a byte[] array myBytes of length 16
    When applet A executes saload on the byte[] reference myBytes with index 0
    Then the JCVM throws ArrayStoreException
    And no data is returned from the type-confused access
    Given applet A has a short[] array myShorts of length 8
    When applet A executes baload on the short[] reference myShorts with index 0
    Then the JCVM throws ArrayStoreException

  # ---------------------------------------------------------------------------
  # Defense: Transaction journal overflow must not corrupt state
  #
  # Hogenboom & Mostowski, WISSEC 2009:
  # If an applet begins a transaction and performs more writes than the
  # transaction journal (commit buffer) can hold, the JCVM must throw
  # TransactionException with reason BUFFER_FULL. It must NOT silently
  # drop journal entries (which would prevent rollback and corrupt state
  # on abort) or allow unbounded journal growth (which could exhaust memory).
  #
  # JCRE 2.2.1 clause 7.6: "If the commit buffer capacity is exceeded,
  # the JCRE shall throw TransactionException with reason BUFFER_FULL."
  # ---------------------------------------------------------------------------

  Scenario: Transaction journal overflow throws TransactionException
    # Hogenboom & Mostowski, WISSEC 2009; JCRE 2.2.1 clause 7.6
    Given applet A is installed with a byte array of length 256
    And the JCVM transaction journal capacity is N bytes
    When applet A calls beginTransaction()
    And applet A writes more than N bytes of persistent state within the transaction
    Then the JCVM throws TransactionException with reason BUFFER_FULL
    And no persistent state has been partially committed
    And the card state is consistent (all writes rolled back)

  # ---------------------------------------------------------------------------
  # Defense: CAP file cross-component offset validation
  #
  # Lancia & Bouffard, CARDIS 2015:
  # The CAP file stores method offsets in both the Descriptor component
  # (used by BCV) and the Class component (used by on-card linker). If
  # these disagree, the linker resolves virtual method calls to arbitrary
  # memory locations. The loader must cross-validate these offsets.
  #
  # JCVM 3.1 Section 6.3: "The JCVM shall verify that method references
  # in the Class component are consistent with the Method component."
  # ---------------------------------------------------------------------------

  Scenario: CAP file with mismatched Class/Descriptor component offsets is rejected
    # Lancia & Bouffard, CARDIS 2015; JCVM 3.1 Section 6.3
    # Attack: Descriptor component has valid method offset 0x0040.
    # Class component public_virtual_method_table has offset 0x0000 (zeroed).
    # On a vulnerable card, the zeroed offset resolves to the start of the
    # Method component, enabling arbitrary code execution.
    Given a CAP file where the Descriptor component method offset is 0x0040
    And the Class component public_virtual_method_table offset is 0x0000 (mismatched)
    When the CAP file is submitted for loading via INSTALL [for load]
    Then the card rejects the CAP file during loading
    And SW indicates a CAP file verification error
    And no executable code from the malformed CAP is installed

  # ---------------------------------------------------------------------------
  # Defense: Shareable interface access control
  #
  # Witteman 2003; Poll et al., CARDIS 2008, Section 3:
  # When applet A requests a Shareable Interface Object from applet B,
  # the JCRE must pass A's correct AID to B's getShareableInterfaceObject.
  # If B returns null (denying access), A must not gain any access.
  # AID spoofing must be prevented by the JCRE -- the client AID is set
  # by the runtime, not by the caller.
  #
  # JCRE 2.2.1 Section 6.2.4: "The JCRE shall set the clientAID parameter
  # to the AID of the requesting applet instance."
  # ---------------------------------------------------------------------------

  Scenario: Shareable interface enforces correct client AID and null denial
    # Witteman 2003; Poll et al., CARDIS 2008; JCRE 2.2.1 Section 6.2.4
    Given applet A is installed with AID [A0 00 00 00 62 01 01]
    And applet B is installed with AID [A0 00 00 00 62 02 01]
    And applet B implements getShareableInterfaceObject that only grants access to AID [A0 00 00 00 62 03 01]
    When applet A calls getShareableInterfaceObject for applet B with parameter 0x00
    Then applet B's getShareableInterfaceObject receives clientAID = [A0 00 00 00 62 01 01]
    And applet B returns null (A's AID is not in the access list)
    And applet A receives null from the JCRE
    And applet A cannot invoke any methods on applet B's shareable interface

  # ---------------------------------------------------------------------------
  # Defense: Exception handler bounds validation
  #
  # Barbu, Hoogvorst & Duc, SECRYPT 2012:
  # A malformed CAP file can set handler_pc to an address outside the
  # method's bytecode range. When an exception is thrown, execution jumps
  # to the crafted address -- potentially into another applet's bytecode.
  # The loader must validate all exception table entries at load time.
  #
  # JCVM spec exception table semantics: "handler_pc shall be a valid
  # bytecode index within the same method's bytecode array."
  # ---------------------------------------------------------------------------

  Scenario: Exception handler with out-of-bounds handler_pc is rejected at load time
    # Barbu, Hoogvorst & Duc, SECRYPT 2012; JCVM spec exception table semantics
    Given a CAP file with a method of bytecode length 32
    And the method's exception table contains an entry with:
      """
      start_pc   = 0x0000
      end_pc     = 0x0010
      handler_pc = 0x0080  (outside method bytecode range [0x0000..0x001F])
      catch_type = 0x0000  (catch-all)
      """
    When the CAP file is submitted for loading via INSTALL [for load]
    Then the card rejects the CAP file during loading
    And SW indicates a CAP file verification error
    And no method with out-of-bounds exception handlers is installed
