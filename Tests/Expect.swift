import Foundation

/// Minimal assertion helpers shared by the test files; main.swift reports the totals.
var failures = 0
var checks = 0

func expect(_ condition: Bool, _ name: String, file: StaticString = #file, line: UInt = #line) {
	checks += 1
	if !condition {
		failures += 1
		print("FAIL \(name) (\(file):\(line))")
	}
}
