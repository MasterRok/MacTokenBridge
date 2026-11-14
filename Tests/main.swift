// Test runner for the pure code in Sources/Shared, built and run by scripts/test.sh.
import Foundation

testECDSASignature()
testPINRetention()

print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
