import logging
from androguard.core.bytecodes.apk import APK

# Configure basic logging for safety if loading fails
logger = logging.getLogger(__name__)

def load_apk(apk_path: str) -> object:
    """
    Loads the APK using androguard and returns the parsed APK object.
    This provides access to the AndroidManifest.xml and application resources.
    """
    try:
        apk_obj = APK(apk_path)
        return apk_obj
    except Exception as e:
        logger.error(f"Error loading APK file: {e}")
        raise ValueError(f"Failed to parse APK at {apk_path}: {e}")

def get_permissions(apk_obj) -> list[str]:
    """
    Returns all permissions declared in the AndroidManifest.xml.
    """
    # androguard normalizes permission names and returns them as a list of strings
    return apk_obj.get_permissions()

def flag_dangerous_permissions(permissions: list[str]) -> list[dict]:
    """
    Cross-references application permissions against a list of dangerous permissions.
    
    Security Risk:
    - High-risk permissions grant access to private user data or hardware. 
    - Attackers exploit compromised apps with these privileges to exfiltrate data,
      intercept multi-factor authentication codes (SMS), or spy via hardware.
    """
    # Map the short names from the requirement to standard Android permission strings
    dangerous_map = {
        "android.permission.READ_SMS": "High",
        "android.permission.READ_CONTACTS": "Medium",
        "android.permission.ACCESS_FINE_LOCATION": "High",
        "android.permission.CAMERA": "High",
        "android.permission.RECORD_AUDIO": "High",
        "android.permission.READ_CALL_LOG": "High",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Medium"
    }
    
    flagged = []
    for perm in permissions:
        # Check if the permission matches directly or ends with our target keywords
        for target, severity in dangerous_map.items():
            if perm == target or perm.endswith(target.split('.')[-1]):
                flagged.append({
                    "permission": perm,
                    "severity": severity
                })
                break  # Avoid duplicate entries for the same permission
                
    return flagged

def get_exported_components(apk_obj) -> list[dict]:
    """
    Lists all Activities, Services, Broadcast Receivers, and Content Providers 
    where android:exported="true".
    
    Security Risk:
    - Exported components can be launched or accessed by *any* other application on the device.
    - If left unsecured, malicious apps can exploit them to trigger internal functions,
      bypass authentication, steal sensitive data, or launch unauthorized screens.
    """
    exported_components = []
    
    # We query the XML element tree provided by androguard for the AndroidManifest
    manifest_xml = apk_obj.get_android_manifest_xml()
    if manifest_xml is None:
        return exported_components

    # Define the mapping between Android XML element tags and clean component types
    component_types = {
        'activity': 'Activity',
        'activity-alias': 'Activity',
        'service': 'Service',
        'receiver': 'Broadcast Receiver',
        'provider': 'Content Provider'
    }
    
    # Locate the <application> element inside the manifest
    application = manifest_xml.find('application')
    if application is not None:
        # Iterate over each component type we want to audit
        for tag, type_label in component_types.items():
            for item in application.iter(tag):
                # Retrieve the component name and its exported attribute
                name = item.get('{http://schemas.android.com/apk/res/android}name')
                exported = item.get('{http://schemas.android.com/apk/res/android}exported')
                
                # If exported is explicitly true, or implicitly true via intent filters (for safety)
                if exported == 'true':
                    exported_components.append({
                        "component": name,
                        "type": type_label,
                        "severity": "Medium"
                    })
                    
    return exported_components

def check_manifest_flags(apk_obj) -> list[dict]:
    """
    Checks the <application> configuration for dangerous development flags:
    - android:usesCleartextTraffic="true"
    - android:debuggable="true"
    
    Security Risks:
    - usesCleartextTraffic: Forces or allows the app to communicate using unencrypted HTTP.
      This opens up users to Man-in-the-Middle (MitM) attacks where data can be sniffed or modified.
    - debuggable: Allows runtime debuggers to attach to the application. Attackers can
      use this in production builds to reverse engineer logic, modify memory, and dump data variables.
    """
    flags_to_check = [
        {"attribute": "usesCleartextTraffic", "severity": "High"},
        {"attribute": "debuggable", "severity": "High"}
    ]
    
    results = []
    manifest_xml = apk_obj.get_android_manifest_xml()
    if manifest_xml is None:
        return results

    application = manifest_xml.find('application')
    
    for flag in flags_to_check:
        found_bool = False
        if application is not None:
            # Look up the namespace-qualified attribute value
            attr_val = application.get(f"{{http://schemas.android.com/apk/res/android}}{flag['attribute']}")
            if attr_val == 'true':
                found_bool = True
                
        results.append({
            "flag": flag['attribute'],
            "found": found_bool,
            "severity": flag['severity']
        })
        
    return results
