//! Menu-bar icon animation: the pinwheel turns slowly while the core is running.
use std::time::Duration;
use tauri::{image::Image, tray::TrayIcon};
use tokio::sync::watch;

/// The artwork is not rotationally symmetric, so the cycle is a full turn;
/// looping any shorter would visibly jump at the wrap point.
const FRAMES: usize = 240;
const STEP_DEGREES: f32 = 360.0 / FRAMES as f32;
/// One revolution; 240 frames of 1.5° each is ~24 fps.
const REVOLUTION: Duration = Duration::from_secs(10);
const FRAME_INTERVAL: Duration = REVOLUTION.checked_div(FRAMES as u32).unwrap();

/// Frame for the time since the animation started. Deriving it from elapsed time
/// (not a tick counter) keeps the speed constant when timer ticks are late.
fn frame_at(elapsed: Duration) -> usize {
    let revolution = REVOLUTION.as_nanos();
    ((elapsed.as_nanos() % revolution) * FRAMES as u128 / revolution) as usize
}

/// Alpha-weighted centre of the artwork. The pinwheel sits slightly off the
/// canvas centre, so turning about the canvas centre would make it wobble.
pub fn centroid(rgba: &[u8], width: u32, height: u32) -> (f32, f32) {
    let (mut x_sum, mut y_sum, mut total) = (0.0f32, 0.0f32, 0.0f32);
    for (i, pixel) in rgba.chunks_exact(4).enumerate() {
        let alpha = f32::from(pixel[3]);
        x_sum += alpha * (i % width as usize) as f32;
        y_sum += alpha * (i / width as usize) as f32;
        total += alpha;
    }
    if total == 0.0 {
        return ((width as f32 - 1.0) / 2.0, (height as f32 - 1.0) / 2.0);
    }
    (x_sum / total, y_sum / total)
}

/// Rotate an RGBA image about `pivot` with bilinear sampling. Interpolation
/// uses premultiplied alpha so transparent pixels do not darken the edges.
pub fn rotate(rgba: &[u8], width: u32, height: u32, pivot: (f32, f32), degrees: f32) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let (sin, cos) = degrees.to_radians().sin_cos();
    let (cx, cy) = pivot;
    let pixel = |x: isize, y: isize| -> [f32; 4] {
        if x < 0 || y < 0 || x >= w as isize || y >= h as isize {
            return [0.0; 4];
        }
        let i = (y as usize * w + x as usize) * 4;
        let a = f32::from(rgba[i + 3]) / 255.0;
        [
            f32::from(rgba[i]) * a,
            f32::from(rgba[i + 1]) * a,
            f32::from(rgba[i + 2]) * a,
            a,
        ]
    };
    let mut out = vec![0; rgba.len()];
    for y in 0..h {
        for x in 0..w {
            // Inverse mapping: find where this output pixel comes from.
            let (dx, dy) = (x as f32 - cx, y as f32 - cy);
            let sx = cos * dx + sin * dy + cx;
            let sy = -sin * dx + cos * dy + cy;
            let (x0, y0) = (sx.floor(), sy.floor());
            let (fx, fy) = (sx - x0, sy - y0);
            let (x0, y0) = (x0 as isize, y0 as isize);
            let mut sum = [0.0f32; 4];
            for (px, py, weight) in [
                (x0, y0, (1.0 - fx) * (1.0 - fy)),
                (x0 + 1, y0, fx * (1.0 - fy)),
                (x0, y0 + 1, (1.0 - fx) * fy),
                (x0 + 1, y0 + 1, fx * fy),
            ] {
                let p = pixel(px, py);
                for c in 0..4 {
                    sum[c] += p[c] * weight;
                }
            }
            let i = (y * w + x) * 4;
            let alpha = sum[3];
            if alpha > 0.0 {
                for c in 0..3 {
                    out[i + c] = (sum[c] / alpha).round().clamp(0.0, 255.0) as u8;
                }
                out[i + 3] = (alpha * 255.0).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    out
}

fn frames(base: &Image<'_>) -> Vec<Image<'static>> {
    let pivot = centroid(base.rgba(), base.width(), base.height());
    (0..FRAMES)
        .map(|n| {
            let rgba = rotate(
                base.rgba(),
                base.width(),
                base.height(),
                pivot,
                n as f32 * STEP_DEGREES,
            );
            Image::new_owned(rgba, base.width(), base.height())
        })
        .collect()
}

/// `TrayIcon::set_icon` clears the macOS template flag, which turns the icon
/// solid white on a light menu bar. Set image and flag together instead.
fn set_template(tray: &TrayIcon, icon: &Image<'static>) {
    let _ = tray.set_icon_with_as_template(Some(icon.clone()), true);
}

/// Animate `tray` while `running` is true and rest on the original frame otherwise.
pub fn animate(tray: TrayIcon, base: Image<'static>, mut running: watch::Receiver<bool>) {
    let frames = frames(&base);
    tauri::async_runtime::spawn(async move {
        loop {
            // Idle until connected; no timer runs while disconnected.
            if running.wait_for(|on| *on).await.is_err() {
                return;
            }
            let mut ticker = tokio::time::interval(FRAME_INTERVAL);
            // A late tick must not trigger a burst of catch-up frames.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let started = tokio::time::Instant::now();
            let mut shown = 0;
            while *running.borrow() {
                tokio::select! {
                    _ = ticker.tick() => {
                        let frame = frame_at(started.elapsed());
                        if frame != shown {
                            shown = frame;
                            set_template(&tray, &frames[frame]);
                        }
                    }
                    changed = running.changed() => if changed.is_err() { return },
                }
            }
            set_template(&tray, &base);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const CENTRE: (f32, f32) = (2.0, 2.0);

    /// A single opaque pixel to the right of centre on a 5x5 canvas.
    fn dot() -> Vec<u8> {
        let mut rgba = vec![0; 5 * 5 * 4];
        let i = (2 * 5 + 4) * 4;
        rgba[i..i + 4].copy_from_slice(&[255, 255, 255, 255]);
        rgba
    }
    fn alpha(rgba: &[u8], x: usize, y: usize) -> u8 {
        rgba[(y * 5 + x) * 4 + 3]
    }

    #[test]
    fn zero_rotation_is_identity_and_quarter_turn_moves_pixels() {
        let rgba = dot();
        assert_eq!(rotate(&rgba, 5, 5, CENTRE, 0.0), rgba);
        // Screen coordinates (y down): a positive angle turns clockwise.
        let turned = rotate(&rgba, 5, 5, CENTRE, 90.0);
        assert_eq!(alpha(&turned, 2, 4), 255);
        assert_eq!(alpha(&turned, 4, 2), 0);
    }

    #[test]
    fn partial_rotation_keeps_colour_and_spreads_alpha_without_dark_fringes() {
        let turned = rotate(&dot(), 5, 5, CENTRE, 20.0);
        let total: u32 = turned.chunks(4).map(|p| u32::from(p[3])).sum();
        assert!(total > 128 && total <= 300, "alpha mass {total}");
        for p in turned.chunks(4).filter(|p| p[3] > 0) {
            assert_eq!(&p[..3], &[255, 255, 255]);
        }
    }

    #[test]
    fn pivot_is_the_alpha_weighted_centre() {
        assert_eq!(centroid(&dot(), 5, 5), (4.0, 2.0));
        assert_eq!(centroid(&[0; 5 * 5 * 4], 5, 5), CENTRE);
        // Rotating about the only opaque pixel leaves it in place.
        let turned = rotate(&dot(), 5, 5, (4.0, 2.0), 90.0);
        assert_eq!(alpha(&turned, 4, 2), 255);
    }

    #[test]
    fn frames_cover_a_full_turn_at_a_smooth_rate() {
        assert_eq!(FRAMES as f32 * STEP_DEGREES, 360.0);
        assert!(
            FRAME_INTERVAL <= Duration::from_millis(42),
            "{FRAME_INTERVAL:?}"
        );
    }

    #[test]
    fn frame_follows_elapsed_time_and_wraps_each_full_turn() {
        assert_eq!(frame_at(Duration::ZERO), 0);
        // Sample mid-frame so integer nanosecond rounding cannot matter.
        let mid = |n: u32| FRAME_INTERVAL * n + FRAME_INTERVAL / 2;
        assert_eq!(frame_at(mid(3)), 3);
        assert_eq!(frame_at(REVOLUTION / 4), FRAMES / 4);
        assert_eq!(frame_at(REVOLUTION / 2), FRAMES / 2);
        assert_eq!(frame_at(REVOLUTION), 0);
        assert_eq!(frame_at(REVOLUTION + mid(7)), 7);
    }
}
