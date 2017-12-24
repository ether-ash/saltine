{ mkDerivation, base, bytestring, libsodium, memory, profunctors
, QuickCheck, stdenv, test-framework, test-framework-quickcheck2
}:
mkDerivation {
  pname = "saltine";
  version = "0.1.0.0";
  src = ./.;
  libraryHaskellDepends = [ base bytestring memory profunctors ];
  libraryPkgconfigDepends = [ libsodium ];
  testHaskellDepends = [
    base bytestring QuickCheck test-framework
    test-framework-quickcheck2
  ];
  description = "Cryptography that's easy to digest (NaCl/libsodium bindings)";
  license = stdenv.lib.licenses.mit;
}
