import Foundation

/// Runs every PKCS#11 call on one thread that lives as long as the helper.
///
/// Some modules keep login state per calling thread. SimplySign: its ThreadsWatchingTread polls
/// callers with pthread_kill(thread, 0) and runs pkislFinalOne (dropping the login and the
/// cloud connection) once a caller has exited. GCD worker threads exit after a few idle
/// seconds, which showed up as "one signature works, then CKR_DEVICE_REMOVED or a crash".
final class P11Thread {
	private let condition = NSCondition()
	private var pending: [() -> Void] = []
	private var thread: Thread?

	init(name: String) {
		let thread = Thread { [unowned self] in
			self.run()
		}
		thread.name = name
		self.thread = thread
		thread.start()
	}

	/// Runs body on the PKCS#11 thread and waits for it.
	///
	/// body is @escaping on purpose: the worker still holds the work item for a moment after
	/// signalling completion, which withoutActuallyEscaping reports as a fatal error.
	func sync<T>(_ body: @escaping () throws -> T) throws -> T {
		if Thread.current === thread {
			return try body()
		}
		var result: Result<T, Error>?
		let done = DispatchSemaphore(value: 0)
		enqueue {
			result = Result { try body() }
			done.signal()
		}
		done.wait()
		return try result!.get()
	}

	private func enqueue(_ work: @escaping () -> Void) {
		condition.lock()
		pending.append(work)
		condition.signal()
		condition.unlock()
	}

	private func run() {
		while true {
			condition.lock()
			while pending.isEmpty {
				condition.wait()
			}
			let work = pending.removeFirst()
			condition.unlock()
			work()
		}
	}
}
