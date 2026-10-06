// Brand icon colour variants (Apple systemBlue palette).
//
//   swiftc -O scripts/icon-variants.swift -o /tmp/icon-variants
//   /tmp/icon-variants recolor <in.png> <out.png>   green artwork -> systemBlue
//   /tmp/icon-variants dark    <in.png> <out.png>   iOS dark appearance (opaque)
//   /tmp/icon-variants tinted  <in.png> <out.png>   iOS tinted appearance (grey)
//   /tmp/icon-variants sample  <in.png> x,y ...     print colour at relative points
//
// `dark`/`tinted` take the original (green) master: background detection relies
// on its saturated backdrop. See desktop/src-tauri/icons/clyntis-v3/README.md.
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

struct Bitmap {
    var width: Int, height: Int
    var data: [UInt8] // RGBA, straight alpha
}

func load(_ path: String) -> Bitmap {
    let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil)!
    let image = CGImageSourceCreateImageAtIndex(src, 0, nil)!
    let (w, h) = (image.width, image.height)
    var data = [UInt8](repeating: 0, count: w * h * 4)
    let ctx = CGContext(data: &data, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
    // Un-premultiply.
    for i in stride(from: 0, to: data.count, by: 4) {
        let a = Double(data[i + 3])
        if a > 0 && a < 255 {
            for c in 0..<3 { data[i + c] = UInt8(min(255, (Double(data[i + c]) * 255 / a).rounded())) }
        }
    }
    return Bitmap(width: w, height: h, data: data)
}

func save(_ bmp: Bitmap, _ path: String, opaque: Bool = false) {
    var data = bmp.data
    for i in stride(from: 0, to: data.count, by: 4) {
        let a = Double(data[i + 3])
        for c in 0..<3 { data[i + c] = UInt8((Double(data[i + c]) * a / 255).rounded()) }
    }
    let ctx = CGContext(data: &data, width: bmp.width, height: bmp.height, bitsPerComponent: 8, bytesPerRow: bmp.width * 4,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: (opaque ? CGImageAlphaInfo.noneSkipLast : CGImageAlphaInfo.premultipliedLast).rawValue)!
    let image = ctx.makeImage()!
    let dest = CGImageDestinationCreateWithURL(URL(fileURLWithPath: path) as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(dest, image, nil)
    precondition(CGImageDestinationFinalize(dest))
}

// MARK: colour helpers
func rgb2hsv(_ r: Double, _ g: Double, _ b: Double) -> (Double, Double, Double) {
    let mx = max(r, g, b), mn = min(r, g, b), d = mx - mn
    var h = 0.0
    if d > 0 {
        if mx == r { h = 60 * ((g - b) / d).truncatingRemainder(dividingBy: 6) }
        else if mx == g { h = 60 * ((b - r) / d + 2) }
        else { h = 60 * ((r - g) / d + 4) }
    }
    if h < 0 { h += 360 }
    return (h, mx == 0 ? 0 : d / mx, mx)
}
func hsv2rgb(_ h: Double, _ s: Double, _ v: Double) -> (Double, Double, Double) {
    let c = v * s, hp = (h.truncatingRemainder(dividingBy: 360) + 360).truncatingRemainder(dividingBy: 360) / 60
    let x = c * (1 - abs(hp.truncatingRemainder(dividingBy: 2) - 1)), m = v - c
    let (r, g, b): (Double, Double, Double) =
        hp < 1 ? (c, x, 0) : hp < 2 ? (x, c, 0) : hp < 3 ? (0, c, x) : hp < 4 ? (0, x, c) : hp < 5 ? (x, 0, c) : (c, 0, x)
    return (r + m, g + m, b + m)
}
func smoothstep(_ a: Double, _ b: Double, _ x: Double) -> Double {
    let t = min(1, max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t)
}


/// Green → Apple systemBlue. Weighted by saturation and hue so the pearl-white
/// blades keep their colour and anti-aliased edges blend continuously.
func recolor(_ r: Double, _ g: Double, _ b: Double) -> (Double, Double, Double) {
    let (h, s, v) = rgb2hsv(r, g, b)
    let hueWeight = smoothstep(95, 115, h) * (1 - smoothstep(195, 215, h))
    let w = smoothstep(0.06, 0.20, s) * hueWeight
    if w == 0 { return (r, g, b) }
    let h2 = 211 + (h - 162) * 0.3
    let v2 = min(1, 0.60 + (v - 0.23) * (0.40 / 0.53))
    let (r2, g2, b2) = hsv2rgb(h2, s, max(v, v2))
    return (r + (r2 - r) * w, g + (g2 - g) * w, b + (b2 - b) * w)
}
/// Smooth estimate of the background's saturation/value at every pixel, from
/// pixels that are certainly background, averaged on a grid and diffused into
/// cells covered by the pinwheel.
struct BackgroundModel {
    let cell = 24
    var cols = 0, rows = 0
    var sat: [Double] = [], val: [Double] = []
    init(_ bmp: Bitmap) {
        cols = (bmp.width + cell - 1) / cell; rows = (bmp.height + cell - 1) / cell
        var sum = [Double](repeating: 0, count: cols * rows * 3)
        for y in 0..<bmp.height { for x in 0..<bmp.width {
            let i = (y * bmp.width + x) * 4
            let (_, s, v) = rgb2hsv(Double(bmp.data[i]) / 255, Double(bmp.data[i + 1]) / 255, Double(bmp.data[i + 2]) / 255)
            guard s > 0.82, v < 0.8 else { continue }
            let c = (y / cell) * cols + x / cell
            sum[c * 3] += s; sum[c * 3 + 1] += v; sum[c * 3 + 2] += 1
        }}
        sat = [Double](repeating: -1, count: cols * rows); val = sat
        for c in 0..<(cols * rows) where sum[c * 3 + 2] > Double(cell * cell) * 0.2 {
            sat[c] = sum[c * 3] / sum[c * 3 + 2]; val[c] = sum[c * 3 + 1] / sum[c * 3 + 2]
        }
        // Fill unknown cells from known neighbours until everything is covered.
        while sat.contains(-1) {
            var nextS = sat, nextV = val
            for y in 0..<rows { for x in 0..<cols where sat[y * cols + x] < 0 {
                var (ss, vv, n) = (0.0, 0.0, 0.0)
                for (dx, dy) in [(-1, 0), (1, 0), (0, -1), (0, 1), (-1, -1), (1, 1), (-1, 1), (1, -1)] {
                    let (nx, ny) = (x + dx, y + dy)
                    guard nx >= 0, ny >= 0, nx < cols, ny < rows, sat[ny * cols + nx] >= 0 else { continue }
                    ss += sat[ny * cols + nx]; vv += val[ny * cols + nx]; n += 1
                }
                if n > 0 { nextS[y * cols + x] = ss / n; nextV[y * cols + x] = vv / n }
            }}
            sat = nextS; val = nextV
        }
    }
    func at(_ x: Int, _ y: Int) -> (Double, Double) {
        // Bilinear between cell centres.
        let fx = min(Double(cols - 1), max(0, (Double(x) + 0.5) / Double(cell) - 0.5))
        let fy = min(Double(rows - 1), max(0, (Double(y) + 0.5) / Double(cell) - 0.5))
        let (x0, y0) = (Int(fx), Int(fy)), (x1, y1) = (min(Int(fx) + 1, cols - 1), min(Int(fy) + 1, rows - 1))
        let (tx, ty) = (fx - Double(x0), fy - Double(y0))
        func lerp(_ a: [Double]) -> Double {
            let top = a[y0 * cols + x0] * (1 - tx) + a[y0 * cols + x1] * tx
            let bottom = a[y1 * cols + x0] * (1 - tx) + a[y1 * cols + x1] * tx
            return top * (1 - ty) + bottom * ty
        }
        return (lerp(sat), lerp(val))
    }
}
/// 1 for the pinwheel, 0 for background. Shadows cast on the background are
/// darker but equally saturated, so only paler or brighter pixels count.
func foreground(_ r: Double, _ g: Double, _ b: Double, background: (Double, Double)) -> Double {
    let (_, s, v) = rgb2hsv(r, g, b)
    let d = max(background.0 - s, v - background.1 - 0.06)
    return smoothstep(0.06, 0.16, d)
}
func mapPixels(_ bmp: inout Bitmap, _ f: (Int, Int, Double, Double, Double) -> (Double, Double, Double)) {
    for y in 0..<bmp.height { for x in 0..<bmp.width {
        let i = (y * bmp.width + x) * 4
        let (r, g, b) = f(x, y, Double(bmp.data[i]) / 255, Double(bmp.data[i + 1]) / 255, Double(bmp.data[i + 2]) / 255)
        bmp.data[i] = UInt8((min(1, max(0, r)) * 255).rounded())
        bmp.data[i + 1] = UInt8((min(1, max(0, g)) * 255).rounded())
        bmp.data[i + 2] = UInt8((min(1, max(0, b)) * 255).rounded())
    }}
}
/// iOS dark/tinted backgrounds: Apple's near-black vertical gradient.
func darkBackground(_ y: Int, _ height: Int) -> Double {
    let t = Double(y) / Double(height - 1)
    return (0x2c + (0x0c - 0x2c) * t) / 255
}

// MARK: commands
let args = CommandLine.arguments
switch args[1] {
case "sample":
    let b = load(args[2])
    for spec in args[3...] {
        let p = spec.split(separator: ",").map { Double($0)! }
        let (x, y) = (Int(p[0] * Double(b.width)), Int(p[1] * Double(b.height)))
        let i = (y * b.width + x) * 4
        let (r, g, bl) = (Double(b.data[i]) / 255, Double(b.data[i + 1]) / 255, Double(b.data[i + 2]) / 255)
        let (h, s, v) = rgb2hsv(r, g, bl)
        print(String(format: "%@ rgb(%3d,%3d,%3d) a=%3d h=%5.1f s=%.2f v=%.2f", spec, b.data[i], b.data[i + 1], b.data[i + 2], b.data[i + 3], h, s, v))
    }
case "recolor":
    var b = load(args[2])
    mapPixels(&b) { _, _, r, g, bl in recolor(r, g, bl) }
    // Keep opaque inputs opaque: iOS app icons must not carry an alpha channel.
    let opaque = stride(from: 3, to: b.data.count, by: 4).allSatisfy { b.data[$0] == 255 }
    save(b, args[3], opaque: opaque)
case "dark", "tinted":
    var b = load(args[2])
    let tinted = args[1] == "tinted"
    let (width, height) = (b.width, b.height)
    let model = BackgroundModel(b)
    // Per-pixel foreground estimate; the pinwheel's tips stay within 0.44 of the
    // width from the centre, so anything further out is background.
    var alpha = [Double](repeating: 0, count: width * height)
    for y in 0..<height { for x in 0..<width {
        let i = (y * width + x) * 4
        let radius = hypot(Double(x) - Double(width) / 2, Double(y) - Double(height) / 2) / Double(width)
        alpha[y * width + x] = foreground(Double(b.data[i]) / 255, Double(b.data[i + 1]) / 255,
                                          Double(b.data[i + 2]) / 255, background: model.at(x, y))
            * (1 - smoothstep(0.44, 0.47, radius))
    }}
    // Background must connect to the canvas edge. Background-coloured pixels
    // enclosed by the pinwheel are occlusion shading on the blades: keep them.
    var outside = [Bool](repeating: false, count: width * height)
    var stack: [Int] = []
    for x in 0..<width { stack.append(x); stack.append((height - 1) * width + x) }
    for y in 0..<height { stack.append(y * width); stack.append(y * width + width - 1) }
    while let p = stack.popLast() {
        guard !outside[p], alpha[p] < 0.5 else { continue }
        outside[p] = true
        let (x, y) = (p % width, p / width)
        if x > 0 { stack.append(p - 1) }; if x < width - 1 { stack.append(p + 1) }
        if y > 0 { stack.append(p - width) }; if y < height - 1 { stack.append(p + width) }
    }
    // Only the silhouette edge (within 3px of the outside) keeps soft alpha;
    // the blades' interior is fully opaque, so no partial pixels show as seams.
    var nearOutside = outside
    for _ in 0..<3 {
        var next = nearOutside
        for p in 0..<(width * height) where !nearOutside[p] {
            let (x, y) = (p % width, p / width)
            if (x > 0 && nearOutside[p - 1]) || (x < width - 1 && nearOutside[p + 1])
                || (y > 0 && nearOutside[p - width]) || (y < height - 1 && nearOutside[p + width]) { next[p] = true }
        }
        nearOutside = next
    }
    for p in 0..<(width * height) where !outside[p] && !nearOutside[p] { alpha[p] = 1 }
    for p in 0..<(width * height) where !outside[p] && nearOutside[p] { alpha[p] = max(alpha[p], 0.5) }
    mapPixels(&b) { x, y, r, g, bl in
        let a = alpha[y * width + x]
        var (fr, fg, fb) = recolor(r, g, bl)
        if tinted {
            // The system tints by luminance; keep the pinwheel's shading.
            let l = 0.2126 * fr + 0.7152 * fg + 0.0722 * fb
            (fr, fg, fb) = (l, l, l)
        }
        let bg = darkBackground(y, height)
        return (bg + (fr - bg) * a, bg + (fg - bg) * a, bg + (fb - bg) * a)
    }
    for i in stride(from: 3, to: b.data.count, by: 4) { b.data[i] = 255 }
    save(b, args[3], opaque: true)
default:
    fatalError("unknown command")
}
