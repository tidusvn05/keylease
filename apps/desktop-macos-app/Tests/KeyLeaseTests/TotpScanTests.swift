import AppKit
import CoreImage.CIFilterBuiltins
import ScreenCaptureKit
import XCTest
@testable import KeyLease

@MainActor
final class TotpScanTests: XCTestCase {
    private let uri = "otpauth://totp/Example:test?secret=JBSWY3DPEHPK3PXP&issuer=Example"

    private func qrImage(_ payload: String) throws -> CGImage {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        let image = try XCTUnwrap(filter.outputImage)
            .transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        return try XCTUnwrap(CIContext().createCGImage(image, from: image.extent))
    }

    func testDecodesTotpButIgnoresOtherQrCodes() throws {
        XCTAssertEqual(HostIntegrations.scanTotpQr(in: try qrImage(uri)), .found(uri))
        for payload in ["https://example.com", "otpauth://hotp/test?secret=JBSWY3DPEHPK3PXP"] {
            XCTAssertEqual(HostIntegrations.scanTotpQr(in: try qrImage(payload)), .noCodeFound)
        }
    }

    func testImageFileAndUnreadableImageHaveDifferentOutcomes() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("qr.png")
        let bitmap = NSBitmapImageRep(cgImage: try qrImage(uri))
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: url)
        let host = HostIntegrations()
        XCTAssertEqual(host.scanTotpQrFromImage(url), .found(uri))
        try Data("not an image".utf8).write(to: url)
        guard case .failed = host.scanTotpQrFromImage(url) else {
            return XCTFail("An unreadable file must report an image error")
        }
    }

    func testBlankImageReportsNoCode() throws {
        let image = CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: 256, height: 256))
        let bitmap = try XCTUnwrap(CIContext().createCGImage(image, from: image.extent))
        XCTAssertEqual(HostIntegrations.scanTotpQr(in: bitmap), .noCodeFound)
    }

    func testExistingPermissionDoesNotRequestAgain() async {
        var requests = 0
        let host = HostIntegrations(
            screenCaptureAccess: { true },
            requestScreenCaptureAccess: { requests += 1; return false },
            screenScan: { .found(self.uri) })
        let result = await host.captureScreenTotp()
        XCTAssertEqual(result, .found(uri))
        XCTAssertEqual(requests, 0)
    }

    func testDeniedPermissionDoesNotCapture() async {
        var captures = 0
        let host = HostIntegrations(
            screenCaptureAccess: { false },
            requestScreenCaptureAccess: { false },
            screenScan: { captures += 1; return .noCodeFound })
        let result = await host.captureScreenTotp()
        XCTAssertEqual(result, .permissionRequired)
        XCTAssertEqual(captures, 0)
    }

    func testNewlyGrantedPermissionContinuesCapture() async {
        var requests = 0
        let host = HostIntegrations(
            screenCaptureAccess: { false },
            requestScreenCaptureAccess: { requests += 1; return true },
            screenScan: { .noCodeFound })
        let result = await host.captureScreenTotp()
        XCTAssertEqual(result, .noCodeFound)
        XCTAssertEqual(requests, 1)
        XCTAssertNotNil(result.hint)
    }

    func testCaptureErrorsDoNotAllBecomePermissionErrors() async {
        for (error, expected) in [
            (NSError(domain: SCStreamErrorDomain, code: -3801),
             TotpScanResult.permissionRequired),
            (NSError(domain: SCStreamErrorDomain, code: -3812),
             .failed("Could not capture the screen. Try again or choose an image.")),
        ] {
            let host = HostIntegrations(
                screenCaptureAccess: { true }, requestScreenCaptureAccess: { false },
                screenScan: { throw error })
            let result = await host.captureScreenTotp()
            XCTAssertEqual(result, expected)
        }
        let host = HostIntegrations(
            screenCaptureAccess: { true }, requestScreenCaptureAccess: { false },
            screenScan: { throw CancellationError() })
        let cancelled = await host.captureScreenTotp()
        XCTAssertEqual(cancelled, .cancelled)
        XCTAssertNil(cancelled.hint)
    }
}
