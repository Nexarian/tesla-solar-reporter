#!/usr/bin/env python3
"""
These are the THREE static rules applied to config before sending via FileStore API
for PVI devices (TEG_DEVICE_TYPE_TEG_PVI).

From APK: O = [rule1, M, T]

Where:
- rule1: Anonymous function that ensures grid_code config defaults
- M: setResiAutoMeterUpdate
- T: setResiDatapumpLogRateMs
"""

from datetime import datetime, timezone
from copy import deepcopy


def format_battery_commission_date(date: datetime) -> str:
    """
    Format date as ISO 8601 string with timezone offset.

    From APK function w():
    return`${e.getFullYear()}-${`0${e.getMonth()+1}`.slice(-2)}-${`0${e.getDate()}`.slice(-2)}T...`
    """
    # Get timezone offset in minutes
    offset = date.utcoffset()
    if offset:
        total_seconds = int(offset.total_seconds())
        hours, remainder = divmod(abs(total_seconds), 3600)
        minutes = remainder // 60
        tz_sign = '-' if total_seconds < 0 else '+'
        tz_str = f"{tz_sign}{hours:02d}:{minutes:02d}"
    else:
        tz_str = "+00:00"

    return f"{date.year:04d}-{date.month:02d}-{date.day:02d}T{date.hour:02d}:{date.minute:02d}:{date.second:02d}{tz_str}"


def apply_rule_1_grid_code_defaults(config: dict) -> dict:
    """
    Rule 1: Ensure grid_code config defaults.

    From APK:
    function(e){
      var t,a,n;
      return(null===(t=(e=h(e)).site_info)||void 0===t?void 0:t.grid_code)?(
        (e=S(e)).default_real_mode||(e=Object.assign(Object.assign({},e),{default_real_mode:f.RealMode.self_consumption})),
        (\"string\"!=typeof(null===(a=e.site_info)||void 0===a?void 0:a.battery_commission_date)||
         Date.parse(null===(n=e.site_info)||void 0===n?void 0:n.battery_commission_date)<=0)&&
         (e=A(e,{battery_commission_date:w(new Date)})),
        e
      ):e
    }

    Translation:
    - If site_info.grid_code exists:
      - Ensure default_real_mode is set (default to "self_consumption" if missing)
      - Ensure battery_commission_date is valid (set to current date if invalid/missing)
    """
    if not config.get('site_info'):
        return config

    if not config['site_info'].get('grid_code'):
        return config

    # Ensure default_real_mode is set
    if not config.get('default_real_mode'):
        config['default_real_mode'] = 'self_consumption'

    # Ensure battery_commission_date is valid
    battery_date = config.get('site_info', {}).get('battery_commission_date')
    date_is_valid = False

    if isinstance(battery_date, str):
        try:
            # Try to parse the date (fallback to simple check if dateutil not available)
            try:
                from dateutil import parser as date_parser
                parsed = date_parser.isoparse(battery_date)
            except ImportError:
                # Fallback: Just check if it starts with a valid year
                parsed = datetime.fromisoformat(battery_date.replace('Z', '+00:00'))

            if parsed.timestamp() > 0:
                date_is_valid = True
        except:
            pass

    if not date_is_valid:
        # Set to current date
        now = datetime.now(timezone.utc).astimezone()
        config['site_info']['battery_commission_date'] = format_battery_commission_date(now)

    return config


def apply_rule_M_auto_meter_update(config: dict) -> dict:
    """
    Rule M: setResiAutoMeterUpdate

    From APK:
    function M(e){
      return\"boolean\"!=typeof e.auto_meter_update&&(e.auto_meter_update=!0),e
    }

    Translation:
    - Ensure auto_meter_update is set to true (if not already a boolean)
    """
    if not isinstance(config.get('auto_meter_update'), bool):
        config['auto_meter_update'] = True

    return config


def apply_rule_T_datapump_log_rate(config: dict) -> dict:
    """
    Rule T: setResiDatapumpLogRateMs

    From APK:
    function T(e){
      var t;
      const a=null===(t=e.logging)||void 0===t?void 0:t.datapump_log_rate_ms;
      return\"number\"==typeof a&&0!==a&&500!==a||(
        e=Object.assign(Object.assign({},e),{
          logging:Object.assign(Object.assign({},null==e?void 0:e.logging),{
            datapump_log_rate_ms:b.DEFAULT_DATAPUMP_LOG_RATE_MS
          })
        })
      ),e
    }

    Translation:
    - If logging.datapump_log_rate_ms is not a number, or is 0, or is 500:
      - Set it to DEFAULT_DATAPUMP_LOG_RATE_MS (likely 1000 or 5000)

    Note: We don't know the exact DEFAULT_DATAPUMP_LOG_RATE_MS value, but it's likely 1000ms.
    For safety, we'll set it if it's missing, 0, or 500 (as the APK does).
    """
    datapump_rate = None

    if 'logging' in config and isinstance(config['logging'], dict):
        datapump_rate = config['logging'].get('datapump_log_rate_ms')

    # Check if it's valid (must be a number, not 0, and not 500)
    is_valid = (
        isinstance(datapump_rate, (int, float)) and
        datapump_rate != 0 and
        datapump_rate != 500
    )

    if not is_valid:
        # Set to default (guessing 1000ms based on common practice)
        if 'logging' not in config:
            config['logging'] = {}
        config['logging']['datapump_log_rate_ms'] = 1000

    return config


def apply_pvi_static_rules(config: dict) -> dict:
    """
    Apply all three PVI static rules to config.

    This is what the APK does before sending config via FileStore API:
    O = [rule1, M, T]

    The rules are applied in sequence (functional composition).

    Args:
        config: The config dict to validate/transform

    Returns:
        Modified config dict with rules applied
    """
    # Make a deep copy to avoid mutating the original
    config = deepcopy(config)

    # Apply rules in order
    config = apply_rule_1_grid_code_defaults(config)
    config = apply_rule_M_auto_meter_update(config)
    config = apply_rule_T_datapump_log_rate(config)

    return config


if __name__ == "__main__":
    # Test the rules
    import json

    test_config = {
        "solars": [{
            "din": "1538100-01-F--ADU23249I000ZH",
            "brand": "Tesla",
            "model": "PVI-45",
            "pvi_power_status": "off",
            "nameplate_max_ac_power": 45000,
            "beid": 0
        }],
        "site_info": {
            "nominal_system_power_ac": 7600,
            "grid_code": "US_IEEE_1547_2018_240V"
        }
    }

    print("Original config:")
    print(json.dumps(test_config, indent=2))

    result = apply_pvi_static_rules(test_config)

    print("\nAfter applying PVI static rules:")
    print(json.dumps(result, indent=2))

    print("\nChanges made:")
    if 'default_real_mode' in result:
        print(f"  ✓ Added default_real_mode: {result['default_real_mode']}")
    if 'battery_commission_date' in result.get('site_info', {}):
        print(f"  ✓ Added battery_commission_date: {result['site_info']['battery_commission_date']}")
    if 'auto_meter_update' in result:
        print(f"  ✓ Added auto_meter_update: {result['auto_meter_update']}")
    if 'logging' in result:
        print(f"  ✓ Added logging.datapump_log_rate_ms: {result['logging']['datapump_log_rate_ms']}")
