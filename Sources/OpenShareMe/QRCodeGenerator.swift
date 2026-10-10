import Foundation
import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins

/// Utility to generate native QR codes and export PNG images using CoreImage.
enum QRCodeGenerator {
    private static let ciContext = CIContext()

    /// Generates a crisp `NSImage` containing the QR code for the given payload string.
    /// - Parameters:
    ///   - text: Payload string to encode in the QR code (e.g., Base64 handshake payload).
    ///   - size: Dimensions in points (width and height).
    /// - Returns: Rendered `NSImage`, or `nil` if generation fails.
    static func generateNSImage(from text: String, size: CGFloat = 200) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"

        guard let outputCIImage = filter.outputImage else {
            return nil
        }

        let extent = outputCIImage.extent
        guard extent.width > 0, extent.height > 0 else {
            return nil
        }

        // Scale without interpolation to maintain sharp, readable QR pixels
        let scaleX = size / extent.width
        let scaleY = size / extent.height
        let transformed = outputCIImage.transformed(by: CGAffineTransform(scaleX: scaleX, y: scaleY))

        guard let cgImage = ciContext.createCGImage(transformed, from: transformed.extent) else {
            return nil
        }

        return NSImage(cgImage: cgImage, size: NSSize(width: size, height: size))
    }

    /// Generates raw PNG bytes for the QR code image.
    static func generatePNGData(from text: String, size: CGFloat = 512) -> Data? {
        guard let nsImage = generateNSImage(from: text, size: size) else {
            return nil
        }
        guard let tiffData = nsImage.tiffRepresentation,
              let bitmap = NSBitmapImageRep(data: tiffData),
              let pngData = bitmap.representation(using: .png, properties: [:]) else {
            return nil
        }
        return pngData
    }

    /// Writes the QR code to a temporary PNG file and opens it in macOS Preview.
    static func openAsPNG(text: String) {
        guard let data = generatePNGData(from: text, size: 512) else {
            NSSound.beep()
            return
        }

        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("OpenShareMe_QR_\(UUID().uuidString.prefix(6)).png")

        do {
            try data.write(to: tempURL)
            NSWorkspace.shared.open(tempURL)
        } catch {
            print("Failed to save temporary PNG file: \(error.localizedDescription)")
            NSSound.beep()
        }
    }
}
