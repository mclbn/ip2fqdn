import warnings

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

from ip2fqdn.common import Finding

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
warnings.filterwarnings("ignore", message="Attribute's length", category=UserWarning)


def der_names(der):
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    return cert_names(cert)


def pem_names(pem):
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("ascii", "replace"))
    except Exception:
        return None
    return cert_names(cert)


def cert_names(cert):
    return _common_names(cert) + _san_names(cert)


def _common_names(cert):
    try:
        attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    except Exception:
        return []
    return [(attribute.value, "CN") for attribute in attributes
            if isinstance(attribute.value, str)]


def _san_names(cert):
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [(name, "SAN") for name in san.value.get_values_for_type(x509.DNSName)]
    except Exception:
        return []


def matches(cert_name_list, wanted):
    for name, _ in cert_name_list:
        candidate = name.lower().rstrip(".")
        if candidate == wanted:
            return True
        if candidate.startswith("*.") and "." in wanted and \
                wanted.split(".", 1)[1] == candidate[2:]:
            return True
    return False


def findings(ip, der, prefix, ctx):
    names = der_names(der) if der else None
    if names is None:
        ctx.count("certificates unreadable")
        return []
    return [Finding(ip, name, f"{prefix} {where}") for name, where in names]
