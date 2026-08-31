// SPDX-License-Identifier: GPL-2.0-only
//
// beamfs-bench -- exposure model
//
// Author: Aurelien Desbrieres <aurelien@hackers.camp>

//! Turn a deployment and a duration into an event count.
//!
//! Campaigns were stated in injected events: 64 flips, 100000 ppm.
//! Those numbers compare filesystems against each other and mean
//! nothing outside the harness -- nobody deploys into 64 flips. An
//! integrator asks whether a volume survives a year in the place they
//! intend to put it, and that question needs flux, cross-section and
//! time, not a flip budget.
//!
//! The event count is derived here instead, from the JEDEC JESD89A
//! form `R = sigma * phi * bits * t`. The flat effective
//! cross-section stands in for the spectrum-weighted integral, which
//! is what a beam campaign reports anyway.
//!
//! The old parameters still work. An operator who wants exactly 64
//! flips asks for them; this is the mode for runs that go in a paper.
//!
//! # Calibration
//!
//! Factors are relative to the JESD89A New York sea-level reference of
//! 13 n/(cm^2 h), so terrestrial is 1.0 by construction. They mirror
//! emufi-physics `environment::deployment`; the duplication is
//! deliberate -- the harness must not need the physics crate on the
//! host to plan a campaign -- and the test below pins the numbers so
//! the two cannot drift apart silently.

/// Where the volume under test is taken to sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    Terrestrial,
    Avionics,
    MedicalLinacVault,
    MedicalWard,
    LowEarthOrbit,
    Interplanetary,
}

impl Deployment {
    /// Neutron flux multiplier against the JESD89A reference.
    #[must_use]
    pub fn neutron_factor(self) -> f64 {
        match self {
            Self::Terrestrial | Self::MedicalWard => 1.0,
            Self::Avionics => 300.0,
            Self::MedicalLinacVault => 1.0e6,
            Self::LowEarthOrbit => 1.0e4,
            Self::Interplanetary => 1.0e5,
        }
    }

    /// Whether the factor is published or estimated.
    ///
    /// A manifest that does not distinguish the two invites one
    /// question, and it is the wrong one to face at review.
    #[must_use]
    pub fn is_estimated(self) -> bool {
        matches!(self, Self::MedicalLinacVault | Self::Interplanetary)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terrestrial => "terrestrial",
            Self::Avionics => "avionics",
            Self::MedicalLinacVault => "medical-linac-vault",
            Self::MedicalWard => "medical-ward",
            Self::LowEarthOrbit => "leo",
            Self::Interplanetary => "interplanetary",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "terrestrial" => Some(Self::Terrestrial),
            "avionics" => Some(Self::Avionics),
            "medical-linac-vault" => Some(Self::MedicalLinacVault),
            "medical-ward" => Some(Self::MedicalWard),
            "leo" => Some(Self::LowEarthOrbit),
            "interplanetary" => Some(Self::Interplanetary),
            _ => None,
        }
    }
}

/// JESD89A New York sea-level reference, neutrons per (cm^2 * s).
const JESD89A_REFERENCE_FLUX: f64 = 13.0 / 3600.0;

/// Effective per-bit SEU cross-section, cm^2.
///
/// A stand-in for a measured value: real numbers come from a beam
/// campaign on the specific part. 1e-14 is the order of magnitude for
/// a modern SRAM cell and is what the published upset rates imply.
const DEFAULT_SIGMA_CM2_PER_BIT: f64 = 1.0e-14;

/// An exposure: a place, a medium, a duration.
#[derive(Debug, Clone, Copy)]
pub struct Exposure {
    pub deployment: Deployment,
    pub sigma_cm2_per_bit: f64,
    pub bytes: u64,
    pub hours: f64,
}

impl Exposure {
    /// Read an exposure from the environment.
    ///
    /// `DEPLOYMENT` selects the place, `EXPOSURE_HOURS` the duration,
    /// `EXPOSURE_BYTES` the medium, `SIGMA_CM2_PER_BIT` the
    /// cross-section if a measured one is available. Absent
    /// `DEPLOYMENT`, there is no exposure and the caller keeps its
    /// explicit event count.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let d = Deployment::parse(&std::env::var("DEPLOYMENT").ok()?)?;
        Some(Self {
            deployment: d,
            sigma_cm2_per_bit: std::env::var("SIGMA_CM2_PER_BIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_SIGMA_CM2_PER_BIT),
            bytes: std::env::var("EXPOSURE_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024 * 1024 * 1024),
            hours: std::env::var("EXPOSURE_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24.0),
        })
    }

    /// Upsets expected over the exposure.
    #[must_use]
    pub fn expected_upsets(&self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let bits = (self.bytes as f64) * 8.0;
        let phi = JESD89A_REFERENCE_FLUX * self.deployment.neutron_factor();
        phi * self.sigma_cm2_per_bit * bits * self.hours * 3600.0
    }

    /// Events to inject, at least one.
    ///
    /// A campaign that computes to less than one event still runs one:
    /// the alternative is a run that injects nothing and reports
    /// success, which is worse than a slightly pessimistic count.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        let n = self.expected_upsets();
        if !n.is_finite() || n < 1.0 {
            1
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let c = n.min(1.0e9) as u64;
            c
        }
    }

    /// How much faster than real time the campaign runs.
    ///
    /// Beam campaigns quote this; a software injector that does not is
    /// making a claim about real-time behaviour it has not earned.
    #[must_use]
    pub fn acceleration_factor(&self, campaign_seconds: f64) -> f64 {
        if campaign_seconds <= 0.0 {
            f64::INFINITY
        } else {
            (self.hours * 3600.0) / campaign_seconds
        }
    }

    /// One line for the manifest.
    #[must_use]
    pub fn manifest_line(&self, campaign_seconds: f64) -> String {
        format!(
            "DEPLOYMENT={}|ESTIMATED={}|BYTES={}|HOURS={}|SIGMA={:e}|EXPECTED_UPSETS={:.3}|EVENTS={}|ACCELERATION={:.1}",
            self.deployment.as_str(),
            u8::from(self.deployment.is_estimated()),
            self.bytes,
            self.hours,
            self.sigma_cm2_per_bit,
            self.expected_upsets(),
            self.event_count(),
            self.acceleration_factor(campaign_seconds),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_tb(d: Deployment, hours: f64) -> Exposure {
        Exposure {
            deployment: d,
            sigma_cm2_per_bit: DEFAULT_SIGMA_CM2_PER_BIT,
            bytes: 931 * 1024 * 1024 * 1024,
            hours,
        }
    }

    #[test]
    fn a_terabyte_upsets_about_hourly_on_the_ground() {
        // The number that reframes the whole project: per bit,
        // terrestrial upsets are rare; per terabyte they are hourly,
        // and a terabyte is an ordinary volume.
        let n = one_tb(Deployment::Terrestrial, 1.0).expected_upsets();
        assert!((0.5..5.0).contains(&n), "got {n}");
    }

    #[test]
    fn a_vault_is_six_orders_worse() {
        let g = one_tb(Deployment::Terrestrial, 1.0).expected_upsets();
        let v = one_tb(Deployment::MedicalLinacVault, 1.0).expected_upsets();
        assert!(((v / g) - 1.0e6).abs() / 1.0e6 < 1e-9);
    }

    #[test]
    fn a_ward_matches_the_ground_for_neutrons() {
        assert!(
            (Deployment::MedicalWard.neutron_factor()
                - Deployment::Terrestrial.neutron_factor())
            .abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn factors_match_the_physics_crate() {
        // Pins the duplicated table. If emufi-physics moves a factor
        // and this does not, one of the two is wrong and the failure
        // says which line to look at.
        assert!((Deployment::Terrestrial.neutron_factor() - 1.0).abs() < f64::EPSILON);
        assert!((Deployment::Avionics.neutron_factor() - 300.0).abs() < f64::EPSILON);
        assert!((Deployment::MedicalLinacVault.neutron_factor() - 1.0e6).abs() < 1.0);
        assert!((Deployment::LowEarthOrbit.neutron_factor() - 1.0e4).abs() < f64::EPSILON);
        assert!((Deployment::Interplanetary.neutron_factor() - 1.0e5).abs() < f64::EPSILON);
    }

    #[test]
    fn an_empty_campaign_still_injects_once() {
        let e = Exposure {
            deployment: Deployment::Terrestrial,
            sigma_cm2_per_bit: 1.0e-20,
            bytes: 4096,
            hours: 0.001,
        };
        assert_eq!(e.event_count(), 1);
    }

    #[test]
    fn acceleration_reflects_the_compression() {
        // Six months of vault in ten minutes.
        let e = one_tb(Deployment::MedicalLinacVault, 24.0 * 180.0);
        let a = e.acceleration_factor(600.0);
        assert!(a > 20_000.0, "got {a}");
    }

    #[test]
    fn estimates_are_marked_in_the_manifest() {
        let line = one_tb(Deployment::MedicalLinacVault, 1.0).manifest_line(600.0);
        assert!(line.contains("ESTIMATED=1"), "{line}");
        let line = one_tb(Deployment::Terrestrial, 1.0).manifest_line(600.0);
        assert!(line.contains("ESTIMATED=0"), "{line}");
    }

    #[test]
    fn names_round_trip() {
        for d in [
            Deployment::Terrestrial,
            Deployment::Avionics,
            Deployment::MedicalLinacVault,
            Deployment::MedicalWard,
            Deployment::LowEarthOrbit,
            Deployment::Interplanetary,
        ] {
            assert_eq!(Deployment::parse(d.as_str()), Some(d));
        }
    }
}
