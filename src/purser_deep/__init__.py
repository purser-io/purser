"""Purser Deep — optional companion analyzers for the harder, heavier
checks the core scanner deliberately leaves out of scope.

Scope (excludes CVE/threat-intel feeds and volumetric DoS, which stay out of
scope):
  * deeper pickle **gadget-chain** heuristics (pivot primitives, chained
    reduces, object-graph complexity) beyond the core's import allowlist;
  * **weight tampering / steganography** detection — hidden data smuggled in
    the low bits of tensors, non-finite/garbage weights — parsed statically
    from safetensors/NumPy without ever loading the model.

Honest scope note: this does NOT detect *trained* backdoors / data poisoning
(learned behavior). That needs model-evaluation tooling and remains out of
scope. These are higher-recall, higher-false-positive *static* heuristics —
run them as a second opinion, not a gate on their own.
"""

__version__ = "0.1.0"
