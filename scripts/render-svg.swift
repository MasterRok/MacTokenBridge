// Renders SVG files to square PNGs with AppKit's own SVG support (no third-party tools).
// usage: swift scripts/render-svg.swift <in.svg> <out.png> <pixels> [<in.svg> <out.png> <pixels> ...]
import AppKit
import ImageIO
import UniformTypeIdentifiers

func fail(_ message: String) -> Never {
	FileHandle.standardError.write(Data("render-svg: \(message)\n".utf8))
	exit(1)
}

let args = Array(CommandLine.arguments.dropFirst())
if args.isEmpty || args.count % 3 != 0 {
	fail("usage: render-svg <in.svg> <out.png> <pixels> ...")
}

for i in stride(from: 0, to: args.count, by: 3) {
	guard let image = NSImage(contentsOfFile: args[i]) else {
		fail("cannot read \(args[i])")
	}
	guard let pixels = Int(args[i + 2]), pixels > 0 else {
		fail("bad size: \(args[i + 2])")
	}
	guard let context = CGContext(
		data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0,
		space: CGColorSpace(name: CGColorSpace.sRGB)!,
		bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
	) else {
		fail("cannot create a \(pixels) px bitmap")
	}
	NSGraphicsContext.saveGraphicsState()
	NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
	image.draw(in: NSRect(x: 0, y: 0, width: pixels, height: pixels))
	NSGraphicsContext.restoreGraphicsState()

	let url = URL(fileURLWithPath: args[i + 1]) as CFURL
	guard let bitmap = context.makeImage(),
		let destination = CGImageDestinationCreateWithURL(url, UTType.png.identifier as CFString, 1, nil)
	else {
		fail("cannot write \(args[i + 1])")
	}
	CGImageDestinationAddImage(destination, bitmap, nil)
	if !CGImageDestinationFinalize(destination) {
		fail("cannot write \(args[i + 1])")
	}
}
