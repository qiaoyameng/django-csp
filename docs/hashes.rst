Using hashes for static inline content
======================================

For pages whose final HTML is known at build time, inline ``<script>`` and
``<style>`` elements can be authorized with CSP hashes instead of a nonce.

``build_hash_manifest()`` parses the final HTML, extracts the contents of real
inline elements, normalizes line endings as browsers do, hashes the original
raw text as UTF-8, and deduplicates identical content while retaining every
source element. External scripts, tags in comments, event handlers, and
``style=""`` attributes are not included.

.. code-block:: python

    from csp.utils import build_hash_manifest, build_policy

    html = render_final_page()
    hashes = build_hash_manifest(html, algorithms=("sha256", "sha384"))
    header = build_policy(
        config={"default-src": ["'self'"]},
        hash_manifest=hashes,
    )

Supported algorithms are ``sha256``, ``sha384``, and ``sha512``.
