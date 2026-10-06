.. _hashes:

Hashes
======

For static pages (e.g. a notification page rendered at build time) a per-request
nonce is not practical. Instead, django-csp can compute CSP `hash-source`
expressions for the inline ``<script>`` and ``<style>`` elements of a finished
HTML document, so the hashes can be baked into the policy at build time.

``csp.hashes.generate_hash_manifest`` is a pure function taking the final HTML
text and an iterable of hash algorithms (``sha256``, ``sha384`` and/or
``sha512``; ``sha256`` by default)::

    from csp.hashes import generate_hash_manifest
    from csp.utils import build_policy

    manifest = generate_hash_manifest(html, algorithms=("sha256",))
    policy = build_policy(hash_manifest=manifest)

Only genuine inline elements are hashed:

* ``<script>`` elements with a ``src`` attribute are skipped (browsers ignore
  their inline content).
* Tags inside HTML comments and plain text are ignored.
* Newlines are normalized (CR/CRLF to LF) exactly as browsers do before
  executing inline content, and the raw text of ``<script>``/``<style>``
  elements is hashed verbatim - entities are *not* decoded.
* Empty elements are skipped, since they execute nothing.

The returned ``HashManifest`` deduplicates identical digests while keeping a
list of ``ElementSource`` locations (element type, index, line and column) for
every occurrence. ``manifest.directive_sources()`` maps ``script-src`` and
``style-src`` to their ``'sha256-...'`` source expressions.

Passing the manifest to ``build_policy`` via the ``hash_manifest`` argument
appends the hash sources to the ``script-src`` and ``style-src`` directives
(creating them if the configuration does not define them), so the hashes in
the emitted header always correspond to the actual document body.

.. note::
   This first version does not generate hashes for event handler attributes
   (e.g. ``onclick``) or ``style`` attributes. Those are governed by
   ``script-src-attr``/``style-src-attr`` and would require ``'unsafe-hashes'``.
