# JavaScript Library Detection

The scanner searches the target page's returned HTML for version strings that
match its jQuery, Bootstrap, and AngularJS filename patterns. It reports each
distinct version found for a library, so a newer reference does not hide an
older version included on the same page.

This is a heuristic, not a dependency inventory. It does not download or parse
JavaScript bundles, inspect runtime state, or discover transitive dependencies.
Confirm findings against the page's actual loaded scripts and the library's
release information.
