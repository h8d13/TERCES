from fido2.hid import CtapHidDevice
from fido2.ctap2.base import Ctap2
from fido2.ctap2.pin import ClientPin

import re

from .handlers import _error, _nf_warn

# Map algorithm codes to names
ALG_NAMES = {-7: "es256", -8: "eddsa", -35: "es384", -36: "es512", -257: "rs256"}


def _fmt_alg(alg) -> str:
    code = alg.get("alg") if isinstance(alg, dict) else alg
    return ALG_NAMES.get(code, str(code)) if code else str(alg)


def get_device_info(dev, idx: int = 0) -> dict:
    """
    Get detailed info for a single FIDO2 device.

    Args:
        dev: CtapHidDevice instance
        idx: Device index for display

    Returns:
        Dict with all device capabilities
    """
    ctap = Ctap2(dev)
    info = ctap.info

    # Get PIN/UV retries if supported
    pin_retries = None
    uv_retries = None
    if info.options.get("clientPin"):
        try:
            client_pin = ClientPin(ctap)
            pin_retries, uv_retries = client_pin.get_pin_retries()
        except Exception:
            pass

    return {
        "device": idx,
        "path": str(dev.descriptor.path),
        "aaguid": info.aaguid.hex() if info.aaguid else None,
        "versions": info.versions,
        "extensions": list(info.extensions) if info.extensions else [],
        "transports": list(info.transports) if info.transports else [],
        "algorithms": [_fmt_alg(alg) for alg in info.algorithms] if info.algorithms else [],
        "options": dict(info.options) if info.options else {},
        "max_msg_size": info.max_msg_size,
        "max_creds_in_list": info.max_creds_in_list,
        "max_cred_id_len": info.max_cred_id_length,
        "max_cred_blob_len": info.max_cred_blob_length,
        "max_large_blob": info.max_large_blob,
        "remaining_rks": info.remaining_disc_creds,
        "min_pin_length": info.min_pin_length,
        "pin_protocols": list(info.pin_uv_protocols) if info.pin_uv_protocols else [],
        "pin_retries": pin_retries,
        "uv_retries": uv_retries,
        "firmware_version": info.firmware_version,
    }


def format_info(d: dict) -> str:
    """Format device info dict for display"""
    lines = [
        f"Device {d['device']}: {d['path']}",
        f"  aaguid: {d['aaguid']}",
        f"  versions: {', '.join(d['versions'])}",
        f"  extensions: {', '.join(d['extensions'])}",
        f"  transports: {', '.join(d['transports'])}",
        f"  algorithms: {', '.join(d['algorithms'])}",
        "  options:",
    ]
    for k, v in d['options'].items():
        lines.append(f"    {k}: {'supported' if v else 'not supported'}")
    lines.extend([
        f"  firmware: {d['firmware_version']}",
        f"  max msg size: {d['max_msg_size']}",
        f"  max creds in list: {d['max_creds_in_list']}",
        f"  max cred id len: {d['max_cred_id_len']}",
        f"  max cred blob: {d['max_cred_blob_len']}",
        f"  max large blob: {d['max_large_blob']}",
        f"  remaining rk(s): {d['remaining_rks']}",
        f"  min pin length: {d['min_pin_length']}",
        f"  pin protocols: {', '.join(str(p) for p in d['pin_protocols'])}",
        f"  pin retries: {d['pin_retries']}",
        f"  uv retries: {d['uv_retries']}",
    ])
    return '\n'.join(lines)


def list_devices() -> list[dict]:
    """
    List available FIDO2 devices (equivalent to fido2-token -L).

    Returns:
        List of device dicts with index and path
    """
    devices = list(CtapHidDevice.list_devices())

    if not devices:
        _nf_warn("No FIDO2 devices found")
        return []

    results = []
    for i, dev in enumerate(devices):
        d = {"index": i, "path": str(dev.descriptor.path)}
        results.append(d)
        print(f"{i}: {d['path']}")

    return results


def info(filter_pattern: str | None = None, device_index: int | None = None) -> dict | list[dict]:
    """
    Get FIDO2 device info (equivalent to fido2-token -I).

    Args:
        filter_pattern: Regex pattern to filter output (e.g. "extension|algorithm")
        device_index: Specific device index to query (None = all devices)

    Returns:
        Device info dict or list of dicts for multiple devices
    """
    devices = list(CtapHidDevice.list_devices())

    if not devices:
        _nf_warn("No FIDO2 devices found")
        return []

    # Collect info
    if device_index is not None:
        if device_index >= len(devices):
            _error(f"Device index {device_index} out of range (found {len(devices)} devices)")
            return {}
        results = [get_device_info(devices[device_index], device_index)]
    else:
        results = [get_device_info(dev, i) for i, dev in enumerate(devices)]

    # Display
    for d in results:
        output = format_info(d)
        if filter_pattern:
            filtered = [line for line in output.split('\n') if re.search(filter_pattern, line, re.I)]
            if filtered:
                print('\n'.join(filtered))
        else:
            print(output)
        print()

    return results[0] if len(results) == 1 else results
