//! Minimal glob matcher used for the synced source patterns.
//!
//! Supported syntax (enough for prompt layouts, no external dependency):
//! * `*`  - any run of characters inside one path segment
//! * `?`  - exactly one character inside one path segment
//! * `**` - zero or more path segments
//!
//! Paths always use `/` separators, independent of the host platform.

pub fn matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    let path = path.trim_matches('/');
    let pat: Vec<&str> = if pattern.is_empty() {
        Vec::new()
    } else {
        pattern.split('/').collect()
    };
    let segs: Vec<&str> = if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    };
    match_segments(&pat, &segs)
}

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.first() {
        None => path.is_empty(),
        Some(&"**") => (0..=path.len()).any(|skip| match_segments(&pattern[1..], &path[skip..])),
        Some(segment) => match path.first() {
            None => false,
            Some(candidate) => {
                wildcard_matches(segment, candidate) && match_segments(&pattern[1..], &path[1..])
            }
        },
    }
}

fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    // Classic greedy matcher with a single backtracking point per `*`.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut star_text) = (None::<usize>, 0usize);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            star_text = t;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_text += 1;
            t = star_text;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn segment_wildcards() {
        assert!(matches(
            "*/bots/*/system_prompt.md",
            "abc/bots/cindy-default/system_prompt.md"
        ));
        assert!(!matches(
            "*/bots/*/system_prompt.md",
            "abc/bots/cindy-default/SOUL.md"
        ));
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "ac"));
    }

    #[test]
    fn recursive_wildcards() {
        assert!(matches("**/*.md", "a.md"));
        assert!(matches("**/*.md", "a/b/c.md"));
        assert!(!matches("**/*.md", "a/b/c.txt"));
        assert!(matches("prompts/**", "prompts/a/b.md"));
        assert!(matches("**", "anything/at/all"));
    }

    #[test]
    fn exact_paths() {
        assert!(matches("a/b/c", "a/b/c"));
        assert!(!matches("a/b/c", "a/b/c/d"));
    }
}
