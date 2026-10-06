.. _decorator-chapter:

====================================
Modifying the Policy with Decorators
====================================

Content Security Policies should be restricted and paranoid by default.  You may, on some views,
need to expand or change the policy. django-csp includes four decorators to help.

All decorators take an optional keyword argument, ``REPORT_ONLY``, which defaults to ``False``. If
set to ``True``, the decorator will update the report-only policy instead of the enforced policy.

``@csp_exempt``
===============

Using the ``@csp_exempt`` decorator disables the CSP header on a given
view.

.. code-block:: python

    from csp.decorators import csp_exempt


    # Will not have a CSP header.
    @csp_exempt()
    def myview(request):
        return render(...)


``@csp_additional``
===================

The ``@csp_additional`` decorator adds an **additional, independently enforced policy** to the
response instead of modifying the main policy. Browsers enforce every policy they receive, so an
additional policy can only further restrict what the main policy allows — it can never widen it.
This is useful when a reusable module wants to tighten the policy for its own views without
depending on (or accidentally loosening) the site-wide policy: unlike ``@csp_update``, which
appends to the main policy's source lists, an additional policy keeps its own source lists.

Each additional policy is processed independently: it gets its own ``default-src`` fallback, its
own nonce handling (a policy only receives the nonce if it opts in via ``csp.constants.NONCE``),
and its own hash and empty-directive handling. The directives of multiple policies are never
merged into a single source union. ``@csp_update`` and ``@csp_replace`` only apply to the main
policy and never touch additional policies.

Enforced and report-only additional policies are stored separately; pass ``REPORT_ONLY=True`` to
add a report-only additional policy. The decorator can be stacked to attach several additional
policies to one view.

.. code-block:: python

    from csp.constants import NONCE, SELF
    from csp.decorators import csp_additional


    # Browsers will enforce both the main policy and this one, so scripts are
    # effectively limited to 'self' regardless of what the main policy allows.
    @csp_additional({"script-src": [SELF]})
    def myview(request):
        return render(...)


    # Stacked decorators attach multiple additional policies. Only the first
    # of these allows nonce'd scripts.
    @csp_additional({"script-src": [SELF, NONCE]})
    @csp_additional({"script-src": [SELF]})
    def myview(request):
        return render(...)

You can also attach additional policies manually by appending directive dicts to the
``_csp_additional`` or ``_csp_additional_ro`` attribute on the response.


    # Will not have a CSP report-only header.
    @csp_exempt(REPORT_ONLY=True)
    def myview(request):
        return render(...)

You can manually set this on a per-response basis by setting the ``_csp_exempt``
or ``_csp_exempt_ro`` attribute on the response to ``True``:

.. code-block:: python

    # Also will not have a CSP header.
    def myview(request):
        response = render(...)
        response._csp_exempt = True
        return response


``@csp_update``
===============

The ``@csp_update`` header allows you to **append** values to the source lists specified in the
settings. If there is no setting, the value passed to the decorator will be used verbatim.

.. note::

   To quote the CSP spec: "There's no inheritance; ... the default list is not used for that
   resource type" if it is set. E.g., the following will not allow images from 'self':

    default-src 'self'; img-src imgsrv.com

The arguments to the decorator are the same as the :ref:`settings <configuration-chapter>`. The
decorator expects a single dictionary argument, where the keys are the directives and the values
are either strings, lists or tuples. An optional argument, ``REPORT_ONLY``, can be set to ``True``
to update the report-only policy instead of the enforced policy.

.. code-block:: python

    from csp.decorators import csp_update


    # Will append imgsrv.com to the list of values for `img-src` in the enforced policy.
    @csp_update({"img-src": "imgsrv.com"})
    def myview(request):
        return render(...)


    # Will append cdn-img.com to the list of values for `img-src` in the report-only policy.
    @csp_update({"img-src": "cdn-img.com"}, REPORT_ONLY=True)
    def myview(request):
        return render(...)


``@csp_replace``
================

The ``@csp_replace`` decorator allows you to **replace** a source list specified in settings. If
there is no setting, the value passed to the decorator will be used verbatim. (See the note under
``@csp_update``.) If the specified value is None, the corresponding key will not be included.

The arguments and values are the same as ``@csp_update``:

.. code-block:: python

    from csp.decorators import csp_replace


    # Will allow images only from imgsrv2.com in the enforced policy.
    @csp_replace({"img-src": "imgsrv2.com"})
    def myview(request):
        return render(...)


    # Will allow images only from cdn-img2.com in the report-only policy.
    @csp_replace({"img-src": "cdn-img2.com"}, REPORT_ONLY=True)
    def myview(request):
        return render(...)

The ``csp_replace`` decorator can also be used to remove a directive from the policy by setting the
value to ``None``. For example, if the ``frame-ancestors`` directive is set in the Django settings
and you want to remove the ``frame-ancestors`` directive from the policy for this view:

.. code-block:: python

    from csp.decorators import csp_replace


    @csp_replace({"frame-ancestors": None})
    def myview(request):
        return render(...)


``@csp``
========

If you need to set the entire policy on a view, ignoring all the settings, you can use the ``@csp``
decorator. This can be stacked to update both the enforced policy and the report-only policy if both
are in use, as shown below.

.. code-block:: python

    from csp.constants import SELF, UNSAFE_INLINE
    from csp.decorators import csp


    @csp(
        {
            "default-src": [SELF],
            "img-src": ["imgsrv.com"],
            "script-src": ["scriptsrv.com", "googleanalytics.com", UNSAFE_INLINE],
        }
    )
    @csp(
        {
            "default-src": [SELF],
            "img-src": ["imgsrv.com"],
            "script-src": ["scriptsrv.com", "googleanalytics.com"],
            "frame-src": [SELF],
        },
        REPORT_ONLY=True,
    )
    def myview(request):
        return render(...)
