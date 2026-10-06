.. _analyzer:

Policy Analyzer
===============

``csp.analyzer`` is a read-only analyzer that explains how a browser would
interpret a Content Security Policy. It accepts either a structured policy
(a directives dict, or a django-csp config dict with a ``"DIRECTIVES"`` key)
or a complete policy string, and never modifies its input.

The analyzer:

- parses the policy and reports duplicate directives (only the first
  occurrence is used, per the spec), invalid source expressions, and
  incompatible keyword combinations such as ``'none'`` mixed with other
  sources;
- resolves, for a given CSP level (2 or 3), the effective source list for
  script elements, script attributes, styles, and common resource types,
  following the fallback chains (for example
  ``script-src-elem`` → ``script-src`` → ``default-src``);
- reports which values are ignored by the rules of the CSP level in use
  (for example host sources ignored when ``'strict-dynamic'`` is present at
  Level 3) and which values come from a fallback directive;
- keeps directives and keywords it cannot identify in an ``unknown`` state
  instead of guessing, so extensions are preserved.

The output is descriptive only. It is **not** a security audit and does not
assign a security score.

Example
-------

.. code-block:: python

    from csp.analyzer import CSP3, analyze, render_text

    report = analyze(
        "default-src 'self'; script-src 'self' 'strict-dynamic' 'nonce-abc123'",
        version=CSP3,
    )
    print(render_text(report))

Multiple policies (for example an enforced and a report-only policy
delivered together) can be analyzed as a list; the report then explains the
intersection semantics browsers apply and traces each effective constraint
back to the policy and directive it came from:

.. code-block:: python

    report = analyze([
        {"DIRECTIVES": {"default-src": ["'self'"], "script-src": ["'self'"]}},
        "script-src 'none'",
    ])
    for note in report.combined:
        print(note)
