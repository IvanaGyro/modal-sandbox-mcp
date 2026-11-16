"""Safe selection of Modal Sandbox container images.

Keep the public tool parameters explicit: registry references, existing named
Modal Images, or existing Modal Image IDs. No arbitrary Dockerfile commands,
registry credentials, build scripts or Modal Secrets are accepted.
"""

from __future__ import annotations

import re
from typing import Literal

ImageSource = Literal["registry", "modal_name", "modal_id"]

# OCI image references (optional registry, tag, or digest), without URL
# credentials, whitespace, shell metacharacters, or URL query strings.
_REGISTRY_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}\Z")
_NAMED_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,126}(?::[A-Za-z0-9._-]{1,128})?\Z")
_ID_REF = re.compile(r"im-[A-Za-z0-9]+\Z")
_PYTHON_VERSION = re.compile(r"3\.(?:10|11|12|13|14|15)(?:\.[0-9]{1,3})?\Z")


def resolve_sandbox_image(
    modal_api,
    default_image,
    image_ref: str | None,
    image_source: ImageSource = "registry",
    image_add_python: str | None = None,
):
    """Return (Image, image metadata) without loading arbitrary build recipes."""
    if image_source not in ("registry", "modal_name", "modal_id"):
        raise ValueError("image_source must be registry, modal_name, or modal_id")
    if image_ref is None:
        if image_add_python is not None or image_source != "registry":
            raise ValueError("Specify image_ref for custom image options")
        return default_image, {"image_source": "default", "image_ref": None}

    if not isinstance(image_ref, str) or not image_ref or len(image_ref) > 255:
        raise ValueError("image_ref must be a nonempty image name up to 255 characters")
    if image_source != "registry" and image_add_python is not None:
        raise ValueError("image_add_python is only valid for registry images")

    if image_source == "registry":
        if (
            not _REGISTRY_REF.fullmatch(image_ref)
            or "://" in image_ref
            or ("@" in image_ref and not re.search(r"@sha256:[a-fA-F0-9]{64}\\Z", image_ref))
        ):
            raise ValueError("Invalid public OCI/Docker registry image reference")
        if image_add_python is not None and (
            not isinstance(image_add_python, str)
            or not _PYTHON_VERSION.fullmatch(image_add_python)
        ):
            raise ValueError("image_add_python must be a supported Python 3 version")
        kwargs = {"add_python": image_add_python} if image_add_python else {}
        image = modal_api.Image.from_registry(image_ref, **kwargs)
    elif image_source == "modal_name":
        if not _NAMED_REF.fullmatch(image_ref):
            raise ValueError("Invalid Modal named image reference")
        image = modal_api.Image.from_name(image_ref)
    else:
        if not _ID_REF.fullmatch(image_ref):
            raise ValueError("Expected Modal Image ID of the form im-...")
        image = modal_api.Image.from_id(image_ref)

    return image, {
        "image_source": image_source,
        "image_ref": image_ref,
        "image_add_python": image_add_python,
    }
