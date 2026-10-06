Policy analysis
===============

``csp.analysis`` is a read-only analyzer for existing policy values. It parses the supplied
configuration, records the source location of every directive and source token, and explains which
sources are effective for common resource types under the selected CSP level.

This is intentionally not a security score. It does not inspect page markup, response headers,
deployment behavior, or every CSP extension. Tokens and directives that the analyzer cannot
interpret are retained with ``unknown`` status.

Analyze a complete policy header value::

    from csp.analysis import analyze_policy

    report = analyze_policy(
        "default-src 'self'; script-src 'self' 'nonce-abc123' 'strict-dynamic'",
        version=3,
    )

    print(report.to_dict())

The same function accepts Django-CSP structured directives::

    from csp.analysis import analyze_policy
    from csp.constants import NONCE, STRICT_DYNAMIC

    report = analyze_policy(
        {"DIRECTIVES": {"script-src": ["'self'", NONCE, STRICT_DYNAMIC]}},
        version=3,
    )

Use :func:`csp.analysis.analyze_csp` with a sequence to analyze several policy values
independently. Each returned object keeps a zero-based ``policy_index`` and, for text policies,
character offsets so findings and effective values can be traced back to the original configuration.

The report contains:

* Parsed directive occurrences, including duplicate and explicitly empty directives.
* Findings for invalid tokens and incompatible source combinations.
* Effective constraints for scripts, script attributes, styles, style attributes, and common
  resource directives.
* ``ignored_values`` and ``fallback_chain`` entries showing values ignored by CSP rules or inherited
  from ``default-src``.
