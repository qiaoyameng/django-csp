.. _reports-chapter:

=====================
CSP Violation Reports
=====================

When something on a page violates the Content-Security-Policy, and the policy defines a
``report-uri`` directive, the user agent may POST a report_. Reports are JSON blobs containing
information about how the policy was violated.

.. note::

    django-csp ships an **optional** report-receiving view (see
    :ref:`receiving-reports` below) but it does not store or analyse reports.
    You can also stand up your own endpoint or use a third-party report
    processing service.

.. _receiving-reports:

Receiving reports in Django
---------------------------
``csp.contrib.reports`` provides a view that accepts both wire formats a
browser may POST:

* ``application/csp-report`` -- the legacy object, ``{"csp-report": {...}}``;
* ``application/reports+json`` -- the Reporting API, a JSON **array** of
  report envelopes (``[{"type": "csp-violation", ...}, ...]``).

Wire it up in your URLconf::

    from csp.contrib.reports import csp_report_view

    urlpatterns = [
        path("csp-report/", csp_report_view),
    ]

Every accepted event is normalised into a ``CSPViolation`` and passed to an
application callback ``callback(request, violation)``.  Supply one with the
factory::

    from csp.contrib.reports import report_view

    def store_violation(request, violation):
        ...

    urlpatterns = [
        path("csp-report/", report_view(store_violation)),
    ]

or point the dotted-path setting ``CSP_REPORT_CALLBACK`` at it.  Without a
callback the view logs a short redacted summary via the ``csp.reports``
logger; it never logs the complete raw request body.

Validated fields
~~~~~~~~~~~~~~~~
Required fields and their types are checked for both formats
(``document-uri``/``documentURL``, ``blocked-uri``/``blockedURL`` -- which may
be the empty string for inline violations -- ``violated-directive``/
``violatedDirective`` and ``disposition``, one of ``enforce`` or ``report``).
The effective directive is taken from ``effective-directive`` when present and
otherwise derived from the first token of the violated directive.  Numeric
fields must be non-negative integers and URI fields must be strings.

URIs such as ``document-uri``, ``blocked-uri``, ``referrer`` and
``source-file`` are **only parsed**, never fetched.  They are normalised
(lower-cased scheme/host) and redacted: userinfo (``user:password@``) and
fragments are removed, and control characters are rejected.

Enforce vs. report-only
~~~~~~~~~~~~~~~~~~~~~~~
The browser's ``disposition`` value is preserved on
``CSPViolation.disposition``: ``"enforce"`` (policy enforced) versus
``"report"`` (report-only policy).  It is never inferred from the endpoint or
header, since one URL can receive both kinds of reports.

Event time
~~~~~~~~~~
``CSPViolation.received_at`` is when the server received the request.
Reporting API reports additionally populate ``occurred_at`` as
``received_at - age``.  Legacy reports have no age information, so
``occurred_at`` is ``None`` and must not be confused with the receive time.

Limits and bad reports
~~~~~~~~~~~~~~~~~~~~~~
The view bounds its work with three limits (override via factory arguments or
settings):

``CSP_REPORT_MAX_BODY_BYTES`` (default 65536)
    Maximum raw request body size; larger requests get HTTP 413.
``CSP_REPORT_MAX_REPORTS`` (default 100)
    Maximum number of elements in a Reporting API array; larger batches get
    HTTP 413.
``CSP_REPORT_MAX_STRING_LENGTH`` (default 1024)
    Maximum length of any string field, including URIs.  Unknown extension
    fields are kept (recursively, depth-limited) but subject to the same cap.

Malformed JSON, unsupported content types and structurally invalid bodies are
rejected with 4xx responses.  Within a Reporting API array, **each element is
validated independently**: valid elements are delivered to the callback and
invalid elements are skipped, with the counts returned in the response
(``{"accepted": n, "rejected": m}``, always HTTP 202 for a parseable array).
Unknown report types (e.g. ``deprecation``) count as rejected elements.

.. warning::

    A ``202 Accepted`` response means the JSON was syntactically valid and
    within the limits **only**.  Report endpoints are unauthenticated, so the
    response is not proof that a genuine browser generated the report or that
    the violation really happened.  Treat report contents as untrusted input;
    do not render them as HTML or act on the included URLs.

Throttling the number of reports
--------------------------------
To throttle the number of requests made to your ``report-uri`` endpoint, you can use
``csp.contrib.rate_limiting.RateLimitedCSPMiddleware`` instead of ``csp.middleware.CSPMiddleware``
and set the ``REPORT_PERCENTAGE`` option:

``REPORT_PERCENTAGE``
    Percentage of requests that should see the ``report-uri`` directive.  Use this to throttle the
    number of CSP violation reports made to your ``report-uri``. A **float** between 0.0 and 100.0
    (0.0 = no reports at all, 100.0 = always report).  Ignored if ``report-uri`` isn't set.

.. _report: http://www.w3.org/TR/CSP/#sample-violation-report
