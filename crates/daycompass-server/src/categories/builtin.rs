//! Built-in categories for well-known Android apps.
//!
//! The fallback [`super::resolve::Resolver::category_for`] uses when
//! none of the account's own rules match, so a fresh account does not
//! see nearly everything as uncategorized. Code, not data: nothing here
//! is stored, events still carry no category, and an account's own
//! `app_id` rule on the same package always wins - that is also how a
//! built-in entry is overridden.
//!
//! Keyed by Android package name only. No domains: Android reports
//! none, and a built-in domain list would be a second, larger thing to
//! keep current.

/// Package name and category. Public identifiers of public apps, no
/// personal data.
const DEFAULTS: &[(&str, &str)] = &[
    // Browser
    ("com.android.chrome", "Browser"),
    ("org.mozilla.firefox", "Browser"),
    ("com.brave.browser", "Browser"),
    ("com.microsoft.emmx", "Browser"),
    ("com.sec.android.app.sbrowser", "Browser"),
    ("com.duckduckgo.mobile.android", "Browser"),
    ("com.opera.browser", "Browser"),
    // Communication
    ("com.whatsapp", "Communication"),
    ("org.telegram.messenger", "Communication"),
    ("org.thoughtcrime.securesms", "Communication"),
    ("com.discord", "Communication"),
    ("com.facebook.orca", "Communication"),
    ("com.google.android.apps.messaging", "Communication"),
    ("com.google.android.gm", "Communication"),
    ("com.microsoft.office.outlook", "Communication"),
    ("com.microsoft.teams", "Communication"),
    ("us.zoom.videomeetings", "Communication"),
    // Social
    ("com.instagram.android", "Social"),
    ("com.instagram.barcelona", "Social"),
    ("com.zhiliaoapp.musically", "Social"),
    ("com.ss.android.ugc.trill", "Social"),
    ("com.snapchat.android", "Social"),
    ("com.facebook.katana", "Social"),
    ("com.twitter.android", "Social"),
    ("com.reddit.frontpage", "Social"),
    ("com.pinterest", "Social"),
    ("com.bereal.ft", "Social"),
    // Video
    ("com.google.android.youtube", "Video"),
    ("com.netflix.mediaclient", "Video"),
    ("com.disney.disneyplus", "Video"),
    ("com.amazon.avod.thirdpartyclient", "Video"),
    ("tv.twitch.android.app", "Video"),
    // Music
    ("com.spotify.music", "Music"),
    ("com.google.android.apps.youtube.music", "Music"),
    ("deezer.android.app", "Music"),
    // Games
    ("com.mojang.minecraftpe", "Games"),
    ("com.roblox.client", "Games"),
    ("com.supercell.brawlstars", "Games"),
    ("com.supercell.clashroyale", "Games"),
    ("com.supercell.clashofclans", "Games"),
    ("com.nianticlabs.pokemongo", "Games"),
    ("com.king.candycrushsaga", "Games"),
    // Education
    ("com.duolingo", "Education"),
    ("com.google.android.apps.classroom", "Education"),
    ("com.ichi2.anki", "Education"),
    ("org.wikipedia", "Education"),
    // Productivity
    ("com.google.android.apps.docs", "Productivity"),
    ("com.google.android.apps.docs.editors.docs", "Productivity"),
    ("com.google.android.calendar", "Productivity"),
    ("com.google.android.keep", "Productivity"),
    ("notion.id", "Productivity"),
    // Navigation
    ("com.google.android.apps.maps", "Navigation"),
    // Shopping
    ("com.amazon.mShop.android.shopping", "Shopping"),
];

/// Every built-in category, sorted, each once.
pub fn names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = DEFAULTS.iter().map(|(_, category)| *category).collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The built-in category for `app_id`, matched exactly like an
/// `app_id` rule: case-sensitive, never trimmed.
pub fn category_for(app_id: &str) -> Option<&'static str> {
    DEFAULTS
        .iter()
        .find(|(id, _)| *id == app_id)
        .map(|(_, category)| *category)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::categories::kind::{normalize_pattern, RuleKind};
    use crate::categories::label::CategoryLabel;

    #[test]
    fn a_known_package_has_its_category_and_an_unknown_one_none() {
        assert_eq!(category_for("com.whatsapp"), Some("Communication"));
        assert_eq!(category_for("COM.WHATSAPP"), None);
        assert_eq!(category_for("org.example.app"), None);
    }

    #[test]
    fn every_entry_is_unique_and_would_pass_as_a_user_rule() {
        let mut seen = HashSet::new();
        for (app_id, category) in DEFAULTS {
            assert!(seen.insert(app_id), "{app_id} is listed twice");
            // A user can only override what an app_id rule can name.
            assert_eq!(
                normalize_pattern(RuleKind::AppId, app_id).as_deref(),
                Ok(*app_id)
            );
            assert_eq!(
                CategoryLabel::parse(category).map(|l| l.as_str().to_owned()),
                Ok((*category).to_owned())
            );
        }
    }
}
