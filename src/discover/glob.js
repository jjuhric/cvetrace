// A minimal, dependency-free glob matcher for --exclude patterns, matched against a
// directory's path relative to the scanned target (forward-slash separated, regardless
// of OS). Supports "*" (any characters except "/"), "?" (single character except "/"),
// and "**" (any characters, including "/"). A pattern ending in "/**" also matches the
// prefix itself (e.g. "test/**" matches both "test" and "test/fixtures/foo"), since
// "skip this directory tree" is the common intent.
export function globToRegExp(pattern) {
  let normalized = pattern.replace(/\\/g, "/");
  let trailingRecursive = false;
  if (normalized.endsWith("/**")) {
    trailingRecursive = true;
    normalized = normalized.slice(0, -3);
  }

  let regexStr = "^";
  for (let i = 0; i < normalized.length; i++) {
    const c = normalized[i];
    if (c === "*") {
      if (normalized[i + 1] === "*") {
        regexStr += ".*";
        i++;
        if (normalized[i + 1] === "/") i++;
      } else {
        regexStr += "[^/]*";
      }
    } else if (c === "?") {
      regexStr += "[^/]";
    } else if (".+^${}()|[]\\".includes(c)) {
      regexStr += `\\${c}`;
    } else {
      regexStr += c;
    }
  }
  regexStr += trailingRecursive ? "(?:/.*)?$" : "$";
  return new RegExp(regexStr);
}

// Builds a (relativePath) => boolean matcher from a list of glob patterns.
export function createExcludeMatcher(patterns) {
  const regexes = (patterns ?? []).map(globToRegExp);
  return (relPath) => {
    const normalized = relPath.replace(/\\/g, "/");
    return regexes.some((re) => re.test(normalized));
  };
}
