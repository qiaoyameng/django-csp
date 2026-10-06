.. _reports-chapter:

=====================
CSP Violation Reports
=====================

When something on a page violates the Content-Security-Policy, and the policy defines a
``report-uri`` directive, the user agent may POST a report_. Modern browsers can also send reports
through the Reporting API when the policy uses ``report-to``.

django-csp provides an optional view that accepts either
``application/csp-report`` or ``application/reports+json``. It validates and normalizes the reports
and then passes the valid events to an application callback. The view is not wired in automatically.

.. warning::

   A ``202 Accepted`` response means only that well-formed reports were accepted by Django. Report
   endpoints are unauthenticated public HTTP endpoints, so accepting a request does not prove that
   the report came from a real browser or that its contents are true. Treat callback data as
   untrusted input.

Basic setup
-----------

Define a callback. It receives the original request and a list of normalized reports::

    # myapp/csp.py
    def store_csp_reports(request, reports):
        for report in reports:
            ...  # Store, enqueue, or otherwise process the report.

Mount the optional view::

    from django.urls import path
    from csp.views import report_receiver
    from myapp.csp import store_csp_reports

    urlpatterns = [
        path(
            "csp-report/",
            report_receiver(callback=store_csp_reports),
            name="csp-report",
        ),
    ]

The callback can also be supplied with the ``CSP_REPORTS`` setting, including as a dotted path. URL
keyword arguments take precedence over settings::

    CSP_REPORTS = {
        "callback": "myapp.csp.store_csp_reports",
        "max_body_size": 65536,
        "max_reports": 100,
        "max_string_length": 2048,
    }

Report limits
-------------

``max_body_size``
    Maximum number of bytes accepted in one request. Bodies larger than this receive ``413``.
    The default is 65,536 bytes.

``max_reports``
    Maximum number of reports in one Reporting API array. Larger arrays receive ``413``. The
    default is 100.

``max_string_length``
    Maximum length accepted for a report string after control characters are removed and URL values
    are normalized. The default is 2,048 characters.

Unknown extension fields are retained separately for the report envelope and CSP report body. They
must still consist of JSON-compatible values and obey the string and collection-size limits.

Normalized reports
------------------

URL-valued fields are normalized with Python's URL parsing utilities and userinfo credentials are
replaced with ``redacted``. URL fragments are omitted. The view never follows, fetches, or resolves
a ``document-uri``, ``blocked-uri``, ``referrer``, or ``source-file`` value.

The normalized object preserves the distinction between:

* ``disposition`` (``"enforce"`` or ``"report"``) and the derived boolean ``report_only``;
* ``violated_directive`` (the complete policy expression supplied by the browser) and
  ``effective_directive`` (the effective directive field, or the directive name derived from
  ``violated_directive`` for legacy reports);
* ``occurred_at``, calculated from a Reporting API report's ``age`` when available, and
  ``received_at``, the server-side time at which the batch was parsed. Legacy ``report-uri`` reports
  do not provide an event age and therefore have ``occurred_at`` set to ``None``.

A Reporting API batch may contain both valid and invalid reports. Invalid array entries are skipped
and counted in the ``X-CSP-Invalid-Reports`` response header; valid entries are still passed to the
callback. A request whose payload is structurally invalid, or where every report fails validation,
receives ``400``. Successful requests receive ``202``.

The default callback is a no-op and does not log the request body, URL values, sample code, policy
text, or other report contents. This avoids writing attacker-controlled report data into logs. If a
custom callback logs data, log only bounded, sanitized fields.

Throttling the number of reports
--------------------------------
To throttle the number of requests made to your ``report-uri`` endpoint, you can use
``csp.contrib.rate_limiting.RateLimitedCSPMiddleware`` instead of ``csp.middleware.CSPMiddleware``
and set the ``REPORT_PERCENTAGE`` option:

``REPORT_PERCENTAGE``
    Percentage of requests that should see the ``report-uri`` directive.  Use this to throttle the
    number of CSP violation reports made to your ``report-uri``. A **float** between 0.0 and 100.0
    (0.0 = no reports at all, 100% = always report).  Ignored if ``report-uri`` isn't set.

.. _report: http://www.w3.org/TR/CSP/#sample-violation-report
