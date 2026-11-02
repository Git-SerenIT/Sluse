// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The look: the design kit's tokens (`ui/look/tokens.css`, D-062),
//! carried into Rust by hand (D-079). Two colours; everything else is a tint
//! between them, mixed as tokens.css mixes it, so nothing here can reach a
//! third hue. The tests hold these to tokens.css, and to the contrast the web
//! console's `contrast.mjs` asked of them.

use iced::{Color, Font, font};

/// One theme's five colours, as `#rrggbb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub surface: u32,
    pub surface_2: u32,
    pub ink: u32,
    pub ink_muted: u32,
    pub line: u32,
}

/// Light and Dark (D-061): navy and SerenIT's #f5f8fb, and their tints.
pub const LIGHT: Theme = Theme { surface: 0xf5f8fb, surface_2: 0xe3e7ed, ink: 0x15294a, ink_muted: 0x4d5d76, line: 0xbdc4cf };
pub const DARK: Theme = Theme { surface: 0x15294a, surface_2: 0x273a58, ink: 0xf5f8fb, ink_muted: 0xb2bac6, line: 0x4d5d76 };

impl Theme {
    pub fn of(dark: bool) -> Theme {
        if dark { DARK } else { LIGHT }
    }
    /// A hovered row.
    #[allow(dead_code)] // the pages' tables, slice 3
    pub fn tint_hover(&self) -> u32 {
        mix(self.ink, 0.05, self.surface_2)
    }
    /// A hovered button.
    pub fn tint_wash(&self) -> u32 {
        mix(self.ink, 0.04, self.surface)
    }
    /// A pressed row or button.
    pub fn tint_press(&self) -> u32 {
        mix(self.ink, 0.10, self.surface_2)
    }
    /// A meter's or a progress bar's track.
    pub fn tint_track(&self) -> u32 {
        mix(self.ink, 0.16, self.surface)
    }
    /// A primary button, hovered.
    pub fn ink_hover(&self) -> u32 {
        mix(self.ink, 0.86, self.surface)
    }
}

/// `color-mix(in srgb, a p%, b)`, rounded per channel as browsers round it.
pub fn mix(a: u32, p: f32, b: u32) -> u32 {
    let ch = |c: u32, s: u32| (c >> s & 0xff) as f32;
    [16, 8, 0].iter().fold(0, |acc, &s| acc | ((ch(a, s) * p + ch(b, s) * (1.0 - p)).round() as u32) << s)
}

pub fn color(hex: u32) -> Color {
    Color::from_rgb8((hex >> 16) as u8, (hex >> 8 & 0xff) as u8, (hex & 0xff) as u8)
}

// Type: Arial, whose metric twin in the box is Liberation Sans (jok,
// 2026-10-19); the terminal's and a path's Liberation Mono.
pub const TEXT: Font = Font::with_name("Liberation Sans");
pub const BOLD: Font = Font { weight: font::Weight::Bold, ..TEXT };
pub const MONO: Font = Font::with_name("Liberation Mono");

pub const H2: f32 = 28.0;
pub const H3: f32 = 20.0;
pub const BODY: f32 = 16.0;
pub const SMALL: f32 = 14.0;
pub const LABEL: f32 = 12.0;
pub const PATH: f32 = 13.0;

pub const S1: f32 = 4.0;
pub const S2: f32 = 8.0;
pub const S3: f32 = 12.0;
pub const S4: f32 = 16.0;
pub const S6: f32 = 24.0;
pub const S8: f32 = 32.0;
pub const S12: f32 = 48.0;

pub const RADIUS_SM: f32 = 4.0;
pub const RADIUS_MD: f32 = 8.0;
pub const RADIUS_PILL: f32 = 999.0;

pub const CONTROL_H: f32 = 36.0;
pub const CONTROL_H_SM: f32 = 32.0;
pub const ICON: f32 = 20.0;
pub const ICON_SM: f32 = 16.0;

#[cfg(test)]
mod tests {
    use super::*;

    /// tokens.css, the copy the shell and Sluse Admin draw with.
    fn tokens() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../ui/look/tokens.css")).unwrap()
    }

    /// Every `--name: #hex` in the block `selector {` opens.
    fn block(css: &str, selector: &str) -> Vec<(String, u32)> {
        let start = css.find(&format!("{selector} {{")).unwrap_or_else(|| panic!("tokens.css has no {selector} block"));
        let body = &css[start..start + css[start..].find('}').unwrap()];
        body.lines()
            .filter_map(|l| {
                let (name, rest) = l.trim().strip_prefix("--")?.split_once(':')?;
                let hex = rest.trim().strip_prefix('#')?.get(..6)?;
                Some((name.to_owned(), u32::from_str_radix(hex, 16).ok()?))
            })
            .collect()
    }

    #[test]
    fn the_colours_are_tokens_css_in_both_themes() {
        let css = tokens();
        for (selector, t) in [("[data-theme=\"light\"]", LIGHT), ("[data-theme=\"dark\"]", DARK)] {
            let b = block(&css, selector);
            let get = |n: &str| b.iter().find(|(k, _)| k == n).map(|(_, v)| *v).unwrap_or_else(|| panic!("{selector}: no --{n}"));
            assert_eq!(
                (t.surface, t.surface_2, t.ink, t.ink_muted, t.line),
                (get("surface"), get("surface-2"), get("ink"), get("ink-muted"), get("line")),
                "{selector}"
            );
        }
    }

    /// WCAG's relative luminance and contrast ratio.
    fn ratio(a: u32, b: u32) -> f64 {
        let lum = |hex: u32| {
            let c = [16, 8, 0].map(|s| {
                let x = f64::from(hex >> s & 0xff) / 255.0;
                if x <= 0.04045 { x / 12.92 } else { ((x + 0.055) / 1.055).powf(2.4) }
            });
            0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
        };
        let (x, y) = (lum(a).max(lum(b)), lum(a).min(lum(b)));
        (x + 0.05) / (y + 0.05)
    }

    /// The pairs contrast.mjs asked of the web console: 4.5 is AA for body
    /// text, 3.0 for a control's edge and the meter's fill on its track.
    #[test]
    fn every_pair_the_console_draws_is_readable() {
        for (name, t) in [("Light", LIGHT), ("Dark", DARK)] {
            let pairs = [
                ("text on the page", t.ink, t.surface, 4.5),
                ("text on a panel", t.ink, t.surface_2, 4.5),
                ("secondary text on the page", t.ink_muted, t.surface, 4.5),
                ("secondary text on a panel", t.ink_muted, t.surface_2, 4.5),
                ("secondary text on a hovered row", t.ink_muted, t.tint_hover(), 4.5),
                ("text on a pressed row", t.ink, t.tint_press(), 4.5),
                ("text on a hovered button", t.ink, t.tint_wash(), 4.5),
                ("a primary button's label", t.surface, t.ink, 4.5),
                ("a primary button's label, hovered", t.surface, t.ink_hover(), 4.5),
                ("a control's edge", t.ink_muted, t.surface, 3.0),
                ("a control's edge on a panel", t.ink_muted, t.surface_2, 3.0),
                ("the meter's fill on its track", t.ink, t.tint_track(), 3.0),
            ];
            for (what, fg, bg, min) in pairs {
                let r = ratio(fg, bg);
                assert!(r >= min, "{name}: {what} is {r:.2}:1, needs {min}");
            }
        }
    }

    #[test]
    fn a_tint_is_mixed_as_tokens_css_mixes_it() {
        // color-mix(in srgb, #15294a 4%, #f5f8fb): each channel rounded.
        assert_eq!(mix(0x15294a, 0.04, 0xf5f8fb), 0xecf0f4);
        assert_eq!(mix(0x000000, 0.5, 0xffffff), 0x808080);
    }
}
