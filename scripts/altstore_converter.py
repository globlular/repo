#!/usr/bin/env python3
"""
AltStore Format Converter
Converts the CyPwn repository format to proper AltStore format
Includes IPA analysis for app permissions extraction
"""

import json
import os
import sys
import subprocess
import requests
import zipfile
import plistlib
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from urllib.parse import urlparse
import re
from typing import Dict, List, Optional, Any

class AltStoreConverter:
    def __init__(self):
        self.permission_mappings = {
            # Privacy descriptions that commonly appear in Info.plist
            'NSCameraUsageDescription': 'Camera access',
            'NSMicrophoneUsageDescription': 'Microphone access',
            'NSPhotoLibraryUsageDescription': 'Photo Library access',
            'NSPhotoLibraryAddUsageDescription': 'Photo Library write access',
            'NSLocationWhenInUseUsageDescription': 'Location access when in use',
            'NSLocationAlwaysAndWhenInUseUsageDescription': 'Location access always',
            'NSContactsUsageDescription': 'Contacts access',
            'NSCalendarsUsageDescription': 'Calendar access',
            'NSRemindersUsageDescription': 'Reminders access',
            'NSMotionUsageDescription': 'Motion and fitness access',
            'NSHealthUpdateUsageDescription': 'Health data write access',
            'NSHealthShareUsageDescription': 'Health data read access',
            'NSBluetoothAlwaysUsageDescription': 'Bluetooth access',
            'NSBluetoothPeripheralUsageDescription': 'Bluetooth peripheral access',
            'NSLocalNetworkUsageDescription': 'Local network access',
            'NSSpeechRecognitionUsageDescription': 'Speech recognition access',
            'NSFaceIDUsageDescription': 'Face ID access',
            'NSAppleMusicUsageDescription': 'Apple Music access',
            'NSMediaLibraryUsageDescription': 'Media library access',
            'NSNearbyInteractionUsageDescription': 'Nearby interaction access'
        }
        
        self.entitlement_mappings = {
            # Core iOS entitlements
            'com.apple.security.application-groups': 'Application groups',
            'com.apple.developer.siri': 'Siri integration',
            'com.apple.developer.healthkit': 'HealthKit access',
            'com.apple.developer.game-center': 'Game Center',
            'com.apple.developer.networking.networkextension': 'Network extensions',
            'com.apple.developer.networking.vpn.api': 'VPN configuration',
            'com.apple.developer.devicecheck.appattest-environment': 'App Attest',
            'com.apple.external-accessory.wireless-configuration': 'Wireless accessory configuration',
            'com.apple.developer.networking.wifi-info': 'WiFi information access',
            'com.apple.developer.networking.multipath': 'Multipath networking',
            'com.apple.developer.associated-domains': 'Associated domains',
            'com.apple.developer.default-data-protection': 'Data protection',
            'com.apple.developer.kernel.increased-memory-limit': 'Increased memory limit',
            'com.apple.developer.kernel.extended-virtual-addressing': 'Extended virtual addressing',
            
            # Key system entitlements
            'keychain-access-groups': 'Keychain access groups',
            'com.apple.developer.team-identifier': 'Team identifier',
            'get-task-allow': 'Debuggable (get-task-allow)',
            'com.apple.security.get-task-allow': 'Debuggable (security variant)',
            
            # iCloud and data sync
            'com.apple.developer.icloud-container-identifiers': 'iCloud containers',
            'com.apple.developer.icloud-services': 'iCloud services',
            'com.apple.developer.ubiquity-kvstore-identifier': 'iCloud key-value storage',
            'com.apple.developer.ubiquity-container-identifiers': 'iCloud document containers',
            
            # Networking entitlements
            'com.apple.developer.networking.HotspotConfiguration': 'Hotspot configuration',
            'com.apple.developer.networking.slicing': 'Network slicing',
            'com.apple.developer.networking.custom-protocol': 'Custom network protocols',
            'com.apple.developer.networking.bluetooth': 'Bluetooth networking',
            
            # Media and content
            'com.apple.developer.coremedia.hls.low-latency': 'Low-latency HLS',
            'com.apple.developer.avfoundation.multitasking-camera-access': 'Background camera access',
            'com.apple.developer.media-device-discovery-extension': 'Media device discovery',
            
            # CarPlay entitlements
            'com.apple.developer.carplay-audio': 'CarPlay audio',
            'com.apple.developer.carplay-communication': 'CarPlay communication',
            'com.apple.developer.carplay-messaging': 'CarPlay messaging',
            'com.apple.developer.carplay-navigation': 'CarPlay navigation',
            'com.apple.developer.carplay-parking': 'CarPlay parking',
            'com.apple.developer.carplay-quick-ordering': 'CarPlay quick ordering',
            'com.apple.developer.carplay-charging': 'CarPlay EV charging',
            'com.apple.developer.carplay-driving-task': 'CarPlay driving task',
            
            # Notifications
            'com.apple.developer.usernotifications.communication': 'Communication notifications',
            'com.apple.developer.usernotifications.critical-alerts': 'Critical alert notifications',
            'com.apple.developer.usernotifications.time-sensitive': 'Time sensitive notifications',
            'aps-environment': 'Push notifications environment',
            
            # Background processing
            'com.apple.developer.background-processing': 'Background processing',
            'com.apple.developer.background-modes': 'Background modes',
            
            # Security and privacy
            'com.apple.security.exception.files.absolute-path.read-only': 'Absolute path file read access',
            'com.apple.security.exception.files.absolute-path.read-write': 'Absolute path file write access',
            'com.apple.security.exception.files.home-relative-path.read-only': 'Home relative file read access',
            'com.apple.security.exception.files.home-relative-path.read-write': 'Home relative file write access',
            'com.apple.security.exception.mach-lookup.global-name': 'Mach service lookup',
            'com.apple.security.exception.shared-preference.read-only': 'Shared preference read access',
            'com.apple.security.exception.shared-preference.read-write': 'Shared preference write access',
            'com.apple.security.temporary-exception.files.absolute-path.read-only': 'Temporary file read access',
            'com.apple.security.temporary-exception.files.absolute-path.read-write': 'Temporary file write access',
            
            # Hardware access
            'com.apple.developer.nfc.readersession.formats': 'NFC reader session',
            'com.apple.developer.nfc.readersession.iso7816.select-identifiers': 'NFC ISO7816 identifiers',
            'com.apple.developer.proximity-reader.payment.acceptance': 'Tap to Pay acceptance',
            
            # App Store and distribution
            'com.apple.developer.in-app-payments': 'In-app payments',
            'com.apple.developer.storekit.external-purchase-link': 'External purchase links',
            
            # System integration
            'com.apple.developer.weatherkit': 'WeatherKit access',
            'com.apple.developer.shared-with-you': 'Shared with You',
            'com.apple.developer.devicecheck.appattest-environment': 'App Attest environment',
            'com.apple.developer.applesignin': 'Sign in with Apple',
            'com.apple.developer.group-session': 'SharePlay group sessions',
            'com.apple.developer.ClassKit-environment': 'ClassKit environment',
            'com.apple.developer.maps': 'MapKit',
            
            # Accessibility
            'com.apple.developer.web-browser-engine.webcontent': 'Web browser engine',
            'com.apple.developer.web-browser-engine.networking': 'Web browser networking',
            'com.apple.developer.web-browser-engine.rendering': 'Web browser rendering',
            
            # Developer tools and debugging
            'com.apple.private.security.no-container': 'No container restriction',
            'com.apple.private.security.storage.AppDataContainers': 'App data container access',
            'com.apple.runningboard.primitiveattribute': 'RunningBoard primitive attributes',
            'com.apple.frontboard.launchapplications': 'Launch applications',
            
            # Legacy and compatibility
            'inter-app-audio': 'Inter-App Audio',
            'application-identifier': 'Application identifier',
            'beta-reports-active': 'Beta reporting',
            
            # Extended entitlements (common in jailbreak/sideload apps)
            'platform-application': 'Platform application',
            'com.apple.private.skip-library-validation': 'Skip library validation',
            'com.apple.private.security.no-sandbox': 'No sandbox restriction',
            'com.apple.springboard.opensensitiveurl': 'Open sensitive URLs',
            'com.apple.multitasking.systemappassertions': 'System app assertions',
            'com.apple.backboardd.launchapplications': 'Backboard launch applications',
            'com.apple.developer.system-extension.install': 'System extension install',
            'com.apple.developer.driverkit': 'DriverKit access',
            'com.apple.developer.kernel.extended-virtual-addressing': 'Extended virtual addressing',
            'com.apple.developer.kernel.increased-memory-limit': 'Increased memory limit'
        }

    def download_and_analyze_ipa(self, download_url: str) -> Dict[str, Any]:
        """Download IPA and extract app permissions from Info.plist and entitlements"""
        print(f"\n🔍 Analyzing IPA: {download_url}")
        
        temp_path = None
        try:
            # Download IPA to temporary file with better error handling
            print("  📥 Downloading IPA...")
            headers = {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15'
            }
            response = requests.get(download_url, stream=True, timeout=60, headers=headers)
            response.raise_for_status()
            
            # Check if we actually got an IPA file
            content_type = response.headers.get('content-type', '')
            if 'application/octet-stream' not in content_type and 'application/zip' not in content_type:
                print(f"  ⚠️  Warning: Unexpected content type: {content_type}")
            
            # Create temp file
            with tempfile.NamedTemporaryFile(suffix='.ipa', delete=False) as temp_file:
                temp_path = temp_file.name
                file_size = 0
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                    file_size += len(chunk)
            
            print(f"  ✅ Downloaded {file_size} bytes")
            
            # Verify it's a valid ZIP/IPA file
            if not zipfile.is_zipfile(temp_path):
                print("  ❌ Downloaded file is not a valid ZIP/IPA file")
                return {'entitlements': [], 'privacy': {}}
            
            # Extract and analyze IPA
            print("  🔬 Analyzing IPA contents...")
            permissions = self.analyze_ipa_file(temp_path)
            
            total_permissions = len(permissions.get('privacy', {})) + len(permissions.get('entitlements', []))
            print(f"  ✅ Analysis complete! Found {total_permissions} permissions")
            
            return permissions
            
        except requests.exceptions.Timeout:
            print("  ❌ Download timed out")
            return {'entitlements': [], 'privacy': {}}
        except requests.exceptions.ConnectionError:
            print("  ❌ Connection error")
            return {'entitlements': [], 'privacy': {}}
        except requests.exceptions.HTTPError as e:
            print(f"  ❌ HTTP error: {e}")
            return {'entitlements': [], 'privacy': {}}
        except Exception as e:
            print(f"  ❌ Error analyzing IPA {download_url}: {e}")
            return {'entitlements': [], 'privacy': {}}
        finally:
            # Always clean up temp file
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                    print("  🗑️  Cleaned up temporary file")
                except Exception as e:
                    print(f"  ⚠️  Warning: Could not delete temp file: {e}")

    def analyze_ipa_file(self, ipa_path: str) -> Dict[str, Any]:
        """Extract app permissions from IPA file using proper macOS tools"""
        permissions = {'entitlements': [], 'privacy': {}}
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zip_file:
                # Find the app bundle
                app_folders = [name for name in zip_file.namelist() 
                             if name.startswith('Payload/') and name.endswith('.app/')]
                
                if not app_folders:
                    print("No app bundle found in IPA")
                    return permissions
                
                app_folder = app_folders[0]
                print(f"Found app bundle: {app_folder}")
                
                # Extract Info.plist for privacy permissions
                info_plist_path = f"{app_folder}Info.plist"
                if info_plist_path in zip_file.namelist():
                    print("Extracting Info.plist...")
                    with zip_file.open(info_plist_path) as plist_file:
                        try:
                            plist_data = plistlib.load(plist_file)
                            
                            # Extract privacy permissions
                            privacy_found = 0
                            for key, description in plist_data.items():
                                if key in self.permission_mappings:
                                    # Use app's description if available and not empty, otherwise use default mapping
                                    if description and isinstance(description, str) and description.strip():
                                        permissions['privacy'][key] = description
                                        print(f"  Found privacy permission: {key} (app description)")
                                    else:
                                        # Use the default mapping for empty/missing descriptions
                                        permissions['privacy'][key] = self.permission_mappings[key]
                                        print(f"  Found privacy permission: {key} (default description)")
                                    privacy_found += 1
                            
                            print(f"  Total privacy permissions found: {privacy_found}")
                            
                        except Exception as e:
                            print(f"Error reading Info.plist: {e}")
                else:
                    print("Info.plist not found in expected location")
                
                # Extract the entire app bundle to a temporary directory for codesign analysis
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Extract all app bundle files
                    app_files = [f for f in zip_file.namelist() if f.startswith(app_folder)]
                    
                    for file_path in app_files:
                        if not file_path.endswith('/'):  # Skip directory entries
                            # Create the directory structure
                            full_path = os.path.join(temp_dir, file_path)
                            os.makedirs(os.path.dirname(full_path), exist_ok=True)
                            
                            # Extract the file
                            with zip_file.open(file_path) as source:
                                with open(full_path, 'wb') as target:
                                    target.write(source.read())
                    
                    # Use codesign to extract entitlements from the app bundle
                    app_path = os.path.join(temp_dir, app_folder)
                    print(f"Using codesign on extracted app bundle: {app_path}")
                    entitlements_from_codesign = self.extract_entitlements_with_codesign(app_path)
                    permissions['entitlements'].extend(entitlements_from_codesign)
                    
                    # Also try to extract from embedded.mobileprovision using security tool
                    mobileprovision_files = [f for f in zip_file.namelist() if 'embedded.mobileprovision' in f]
                    if mobileprovision_files:
                        mobileprovision_path = os.path.join(temp_dir, mobileprovision_files[0])
                        if os.path.exists(mobileprovision_path):
                            print(f"Using security tool on mobileprovision: {mobileprovision_path}")
                            entitlements_from_provision = self.extract_mobileprovision_with_security(mobileprovision_path)
                            
                            # Add any new entitlements we haven't seen yet
                            for ent in entitlements_from_provision:
                                if ent not in permissions['entitlements']:
                                    permissions['entitlements'].append(ent)
                    
                # Remove duplicates and sort
                permissions['entitlements'] = sorted(list(set(permissions['entitlements'])))
                
        except Exception as e:
            print(f"Error analyzing IPA file: {e}")
        
        return permissions

    def extract_entitlements_with_codesign(self, app_bundle_path):
        """Extract entitlements using codesign tool"""
        entitlements = []
        
        try:
            # Use codesign to extract entitlements
            result = subprocess.run([
                'codesign', '-d', '--entitlements', ':-', app_bundle_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                print("  Using codesign to extract entitlements...")
                try:
                    # Parse the entitlements plist
                    entitlements_data = plistlib.loads(result.stdout.encode('utf-8'))
                    
                    entitlements_found = 0
                    for key in entitlements_data.keys():
                        if key in self.entitlement_mappings:
                            entitlements.append(key)
                            entitlements_found += 1
                            print(f"  Found entitlement (codesign): {key}")
                    
                    print(f"  Total entitlements found with codesign: {entitlements_found}")
                    
                except Exception as parse_e:
                    print(f"  Could not parse codesign output: {parse_e}")
            else:
                print(f"  codesign failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("  codesign timed out")
        except Exception as e:
            print(f"  Error running codesign: {e}")
        
        return entitlements

    def extract_mobileprovision_with_security(self, mobileprovision_path):
        """Extract entitlements from mobileprovision using security tool"""
        entitlements = []
        
        try:
            # Use security tool to decode the mobileprovision
            result = subprocess.run([
                'security', 'cms', '-D', '-i', mobileprovision_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                print("  Using security tool to decode mobileprovision...")
                try:
                    # Parse the decoded plist
                    plist_data = plistlib.loads(result.stdout.encode('utf-8'))
                    
                    if 'Entitlements' in plist_data:
                        entitlements_dict = plist_data['Entitlements']
                        entitlements_found = 0
                        
                        for key in entitlements_dict.keys():
                            if key in self.entitlement_mappings:
                                entitlements.append(key)
                                entitlements_found += 1
                                print(f"  Found entitlement (security): {key}")
                        
                        print(f"  Total entitlements found with security tool: {entitlements_found}")
                    else:
                        print("  No 'Entitlements' key found in mobileprovision")
                        
                except Exception as parse_e:
                    print(f"  Could not parse security tool output: {parse_e}")
            else:
                print(f"  security tool failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("  security tool timed out")
        except Exception as e:
            print(f"  Error running security tool: {e}")
        
        return entitlements

    def format_date(self, date_str: str) -> str:
        """Convert various date formats to ISO format"""
        if not date_str:
            return datetime.now().strftime("%Y-%m-%dT%H:%M:%S-08:00")
        
        # If already has time, keep it
        if 'T' in date_str:
            return date_str
        
        # Add time to date-only strings
        return f"{date_str}T00:00:00-08:00"

    def generate_screenshot_urls(self, app_name: str, base_url: str = None) -> List[str]:
        """Generate screenshot URLs based on app name - only as fallback"""
        screenshots = []
        
        # Only generate as absolute fallback if no existing screenshots
        # Most apps should already have screenshots in the source data
        if base_url:
            safe_name = re.sub(r'[^\w\-_.]', '_', app_name)
            # Just try one screenshot as fallback
            screenshot_url = f"{base_url}/serve/screenshots/{app_name}/{safe_name}-0.png"
            screenshots.append(screenshot_url)
        
        return screenshots

    def convert_app_to_altstore_format(self, app: Dict[str, Any], analyze_ipa: bool = False) -> Dict[str, Any]:
        """Convert a single app from CyPwn format to AltStore format"""
        
        # Skip empty apps
        if not app or not app.get('name') or not app.get('bundleIdentifier'):
            return None
        
        # Create base app structure - preserve all existing fields where appropriate
        altstore_app = {
            'name': app.get('name', ''),
            'bundleIdentifier': app.get('bundleIdentifier', ''),
            'developerName': app.get('developerName', ''),
            'localizedDescription': app.get('localizedDescription', ''),
            'iconURL': app.get('iconURL', ''),
            'tintColor': app.get('tintColor', 'FFC300')
        }
        
        # Add subtitle if it exists
        if app.get('subtitle'):
            altstore_app['subtitle'] = app['subtitle']
        
        # Handle screenshots - prioritize existing data
        if 'screenshotURLs' in app and app['screenshotURLs']:
            # Use existing screenshotURLs array
            altstore_app['screenshots'] = app['screenshotURLs']
        elif 'screenshots' in app and app['screenshots']:
            # Use existing screenshots field
            altstore_app['screenshots'] = app['screenshots']
        else:
            # Only generate screenshot URLs as absolute fallback
            base_url = app.get('iconURL', '').split('/serve/icons/')[0] if 'serve/icons' in app.get('iconURL', '') else None
            if base_url:
                fallback_screenshots = self.generate_screenshot_urls(app['name'], base_url)
                if fallback_screenshots:
                    altstore_app['screenshots'] = fallback_screenshots
        
        # Create versions array
        if 'versions' not in app:
            # Convert from old format
            version_data = {
                'version': app.get('version', '1.0'),
                'date': self.format_date(app.get('versionDate', '')),
                'size': app.get('size', 0),
                'downloadURL': app.get('downloadURL', ''),
                'localizedDescription': app.get('localizedDescription', '')
            }
            
            # Add intelligent minimum OS version based on app name
            app_name_lower = app.get('name', '').lower()
            if 'ios15' in app_name_lower or 'w15' in app_name_lower:
                version_data['minOSVersion'] = '15.0'
            elif 'ios16' in app_name_lower:
                version_data['minOSVersion'] = '16.0'
            elif 'ios14' in app_name_lower:
                version_data['minOSVersion'] = '14.0'
            elif 'minOSVersion' in app:
                version_data['minOSVersion'] = app['minOSVersion']
            else:
                version_data['minOSVersion'] = '13.0'  # Safe default
            
            altstore_app['versions'] = [version_data]
        else:
            altstore_app['versions'] = app['versions']
        
        # Analyze IPA for permissions if requested
        if analyze_ipa and altstore_app['versions']:
            download_url = altstore_app['versions'][0].get('downloadURL')
            if download_url:
                permissions = self.download_and_analyze_ipa(download_url)
                if permissions and (permissions.get('entitlements') or permissions.get('privacy')):
                    # Clean up empty arrays/dicts
                    clean_permissions = {}
                    if permissions.get('entitlements'):
                        clean_permissions['entitlements'] = permissions['entitlements']
                    if permissions.get('privacy'):
                        clean_permissions['privacy'] = permissions['privacy']
                    
                    if clean_permissions:
                        altstore_app['appPermissions'] = clean_permissions
        
        return altstore_app

    def convert_repository(self, input_file: str, output_file: str, analyze_ipas: bool = False):
        """Convert entire repository from CyPwn format to AltStore format"""
        
        print(f"🚀 Converting {input_file} to AltStore format...")
        if analyze_ipas:
            print("🔍 IPA analysis enabled - this will download and analyze each app!")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Convert apps
        converted_apps = []
        skipped_apps = 0
        total_apps = len(data.get('apps', []))
        
        for i, app in enumerate(data.get('apps', []), 1):
            app_name = app.get('name', 'Unknown')
            print(f"\n{'='*60}")
            print(f"Processing app {i}/{total_apps}: {app_name}")
            print(f"{'='*60}")
            
            try:
                converted_app = self.convert_app_to_altstore_format(app, analyze_ipa=analyze_ipas)
                if converted_app:
                    converted_apps.append(converted_app)
                    print(f"✅ Successfully converted: {app_name}")
                else:
                    skipped_apps += 1
                    print(f"⚠️  Skipped incomplete app: {app_name}")
            except Exception as e:
                skipped_apps += 1
                print(f"❌ Error converting app {app_name}: {e}")
                continue
        
        # Update the data structure
        data['apps'] = converted_apps
        
        # Ensure required fields exist
        if 'identifier' not in data:
            data['identifier'] = 'com.converted.source'
        
        if 'sourceURL' not in data:
            data['sourceURL'] = f"https://example.com/{os.path.basename(output_file)}"
        
        # Write converted data
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"\n{'='*60}")
        print(f"🎉 CONVERSION COMPLETE!")
        print(f"✅ Successfully converted: {len(converted_apps)} apps")
        print(f"⚠️  Skipped: {skipped_apps} apps")
        print(f"📄 Output saved to: {output_file}")
        print(f"{'='*60}")

    def batch_convert(self, input_directory: str, output_directory: str, analyze_ipas: bool = False):
        """Batch convert all JSON files in a directory"""
        
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
        
        json_files = [f for f in os.listdir(input_directory) if f.endswith('.json')]
        
        for json_file in json_files:
            input_path = os.path.join(input_directory, json_file)
            output_path = os.path.join(output_directory, f"converted_{json_file}")
            
            print(f"\n{'='*50}")
            print(f"Converting {json_file}")
            print(f"{'='*50}")
            
            try:
                self.convert_repository(input_path, output_path, analyze_ipas)
            except Exception as e:
                print(f"Error converting {json_file}: {e}")

def main():
    converter = AltStoreConverter()
    
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Single file: python altstore_converter.py input.json output.json [--analyze-ipas]")
        print("  Batch mode:  python altstore_converter.py input_dir/ output_dir/ [--analyze-ipas]")
        return
    
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    analyze_ipas = '--analyze-ipas' in sys.argv
    
    if analyze_ipas:
        print("⚠️  IPA analysis enabled - this will take significantly longer!")
        print("    Downloads will be made to analyze app permissions.")
    
    if os.path.isdir(input_path):
        # Batch mode
        converter.batch_convert(input_path, output_path, analyze_ipas)
    else:
        # Single file mode
        converter.convert_repository(input_path, output_path, analyze_ipas)

if __name__ == "__main__":
    main()
