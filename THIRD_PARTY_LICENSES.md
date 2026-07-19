# Third-Party Licenses

Purser is licensed under **Apache-2.0** (see [`LICENSE`](LICENSE)). It
bundles the third-party Python packages below in its distributed container
images. This file is **auto-generated** from the CycloneDX SBOM(s) — do not
edit by hand; regenerate with `make licenses`.

Sources: `purser-core.cdx.json`, `purser-hf.cdx.json`, `purser-deep.cdx.json`
Total distributed dependencies: **39**

## License summary

| License | Packages |
|---|---|
| Apache-2.0 | 3 |
| Apache-2.0 OR BSD-2-Clause | 1 |
| Apache-2.0 OR BSD-3-Clause | 1 |
| Apache-2.0 OR MIT | 1 |
| BSD-2-Clause | 1 |
| BSD-3-Clause | 11 |
| ISC | 1 |
| MIT | 16 |
| MIT-0 | 1 |
| MPL-2.0 | 1 |
| MPL-2.0 AND MIT | 1 |
| PSF-2.0 | 1 |

> All licenses are permissive (MIT/BSD/Apache/ISC/PSF). The only copyleft is
> **MPL-2.0** (e.g. certifi, and tqdm as MPL-2.0/MIT) — a weak, file-level
> copyleft satisfied by shipping the package unmodified; take MIT where dual.
> No GPL/AGPL/LGPL is present in the Python dependency tree. The container
> base (Wolfi + CPython/PSF + OS packages) carries its own licenses.

## Dependencies

| Package | Version | License |
|---|---|---|
| `annotated-doc` | 0.0.4 | MIT |
| `annotated-types` | 0.7.0 | MIT |
| `anyio` | 4.14.2 | MIT |
| `certifi` | 2026.6.17 | MPL-2.0 |
| `cffi` | 2.1.0 | MIT-0 |
| `click` | 8.4.2 | BSD-3-Clause |
| `cryptography` | 49.0.0 | Apache-2.0 OR BSD-3-Clause |
| `fastapi` | 0.139.2 | MIT |
| `filelock` | 3.30.3 | MIT |
| `fsspec` | 2026.6.0 | BSD-3-Clause |
| `h11` | 0.16.0 | MIT |
| `hf-xet` | 1.5.2 | Apache-2.0 |
| `httpcore` | 1.0.9 | BSD-3-Clause |
| `httptools` | 0.8.0 | MIT |
| `httpx` | 0.28.1 | BSD-3-Clause |
| `huggingface-hub` | 1.24.0 | Apache-2.0 |
| `idna` | 3.18 | BSD-3-Clause |
| `markdown-it-py` | 4.2.0 | MIT |
| `mdurl` | 0.1.2 | MIT |
| `packaging` | 26.2 | Apache-2.0 OR BSD-2-Clause |
| `pycparser` | 3.0 | BSD-3-Clause |
| `pydantic` | 2.13.4 | MIT |
| `pydantic-core` | 2.46.4 | MIT |
| `pygments` | 2.20.0 | BSD-2-Clause |
| `python-dotenv` | 1.2.2 | BSD-3-Clause |
| `python-multipart` | 0.0.32 | Apache-2.0 |
| `pyyaml` | 6.0.3 | MIT |
| `rich` | 15.0.0 | MIT |
| `shellingham` | 1.5.4 | ISC |
| `starlette` | 1.3.1 | BSD-3-Clause |
| `tqdm` | 4.69.0 | MPL-2.0 AND MIT |
| `typer` | 0.27.0 | MIT |
| `typing-extensions` | 4.16.0 | PSF-2.0 |
| `typing-inspection` | 0.4.2 | MIT |
| `uvicorn` | 0.51.0 | BSD-3-Clause |
| `uvloop` | 0.22.1 | Apache-2.0 OR MIT |
| `watchfiles` | 1.2.0 | MIT |
| `websockets` | 16.1 | BSD-3-Clause |
| `websockets` | 16.1.1 | BSD-3-Clause |

Full license texts are available in each package's distribution and via its PyPI project page (purl in the SBOM).
