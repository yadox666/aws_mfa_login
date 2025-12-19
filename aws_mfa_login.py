#!/usr/bin/env python3
"""
AWS MFA Authentication Manager
Cross-platform tool to authenticate AWS profiles using MFA tokens.
Supports macOS, Linux, and Windows.
"""

import argparse
import configparser
import logging
import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("Error: boto3 is required. Install with: pip3 install boto3")
    sys.exit(1)

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        load_dotenv(env_file)
except ImportError:
    pass  # dotenv is optional


AWS_CREDENTIALS_FILE = Path.home() / ".aws" / "credentials"
AWS_CONFIG_FILE = Path.home() / ".aws" / "config"
AWS_DEACTIVATED_KEYS_FILE = Path.home() / ".aws" / "credentials.deactivated"
LONG_TERM_SUFFIX = "-long-term"
DEFAULT_SESSION_DURATION = 43200  # 12 hours
OUTPUT_DIR = Path(__file__).parent / "output"
AWS_KEY_EXPIRATION_DAYS = int(os.environ.get('AWS_KEY_EXPIRATION_DAYS', 180))
AWS_KEY_WARNING_DAYS = int(os.environ.get('AWS_KEY_WARNING_DAYS', 30))
MFA_TOKEN_LENGTH = 6  # Standard MFA token length
MFA_MAX_ATTEMPTS = 3  # Maximum retry attempts for MFA authentication

# Custom User-Agent suffix for AWS API calls
BOTO_CONFIG = Config(user_agent_extra='aws-mfa-login/1.0')


def get_display_name(profile: str) -> str:
    """Get display name by removing -long-term suffix."""
    if profile.endswith(LONG_TERM_SUFFIX):
        return profile[:-len(LONG_TERM_SUFFIX)]
    return profile


def get_long_term_name(display_name: str) -> str:
    """Get the actual long-term profile name from display name."""
    if not display_name.endswith(LONG_TERM_SUFFIX):
        return f"{display_name}{LONG_TERM_SUFFIX}"
    return display_name

# Global logger
logger = logging.getLogger("aws_mfa_login")


def setup_logging(debug: bool = False):
    """Configure logging to file and optionally to console in debug mode."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    log_file = OUTPUT_DIR / f"aws_mfa_{datetime.now().strftime('%Y%m%d')}.log"
    
    # Set log level based on debug flag
    log_level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(log_level)
    
    # File handler - always logs INFO and above
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    # Console handler - only in debug mode
    if debug:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_format = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
    
    logger.debug(f"Logging initialized. Log file: {log_file}")


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║           AWS MFA Authentication Manager                  ║
║            macOS · Linux · Windows                        ║
╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
    print(banner)


def print_success(msg: str):
    print(f"{Colors.GREEN}✓ {msg}{Colors.ENDC}")
    logger.info(f"SUCCESS: {msg}")


def print_error(msg: str):
    print(f"{Colors.RED}✗ {msg}{Colors.ENDC}")
    logger.error(msg)


def print_warning(msg: str):
    print(f"{Colors.RED}⚠ {msg}{Colors.ENDC}")
    logger.warning(msg)


def print_info(msg: str):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.ENDC}")
    logger.info(msg)


def load_credentials() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    if AWS_CREDENTIALS_FILE.exists():
        config.read(AWS_CREDENTIALS_FILE)
        logger.debug(f"Loaded credentials from {AWS_CREDENTIALS_FILE}")
    else:
        logger.debug(f"Credentials file not found: {AWS_CREDENTIALS_FILE}")
    return config


def load_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    if AWS_CONFIG_FILE.exists():
        config.read(AWS_CONFIG_FILE)
    return config


def save_credentials(config: configparser.ConfigParser):
    with open(AWS_CREDENTIALS_FILE, 'w') as f:
        config.write(f)


def get_long_term_profiles(credentials: configparser.ConfigParser) -> List[str]:
    """Get profiles that have long-term credentials (ending with -long-term suffix)."""
    long_term = []
    for section in credentials.sections():
        # Only consider profiles ending with -long-term
        if not section.endswith(LONG_TERM_SUFFIX):
            continue
        if credentials.has_option(section, 'aws_access_key_id') and \
           credentials.has_option(section, 'aws_secret_access_key'):
            if not credentials.has_option(section, 'aws_session_token'):
                long_term.append(section)
            elif credentials.get(section, 'aws_session_token', fallback='').strip() == '':
                long_term.append(section)
    return long_term


def get_mfa_serial(profile: str) -> Optional[str]:
    """Get MFA serial ARN from config file or credentials file only.
    
    Note: Does NOT query IAM to avoid CloudTrail events before MFA authentication.
    User must configure mfa_serial or aws_mfa_device in credentials or config file, or enter it manually.
    
    Checks for both 'mfa_serial' and 'aws_mfa_device' (aws-mfa tool compatibility).
    """
    logger.debug(f"Looking up MFA serial for profile: {profile}")
    
    # Check config file first (~/.aws/config)
    config = load_config()
    profile_section = f"profile {profile}" if profile != "default" else "default"
    
    for key in ['mfa_serial', 'aws_mfa_device']:
        if config.has_option(profile_section, key):
            mfa_serial = config.get(profile_section, key)
            logger.debug(f"Found MFA serial ({key}) in config file: {mfa_serial}")
            return mfa_serial
    
    # Check credentials file (~/.aws/credentials)
    credentials = load_credentials()
    for key in ['mfa_serial', 'aws_mfa_device']:
        if credentials.has_option(profile, key):
            mfa_serial = credentials.get(profile, key)
            logger.debug(f"Found MFA serial ({key}) in credentials file: {mfa_serial}")
            return mfa_serial
    
    logger.debug(f"MFA serial not found in config files for {profile}")
    return None


def backup_deactivated_key(profile: str, access_key_id: str, secret_access_key: str):
    """Backup a deactivated key to the credentials.deactivated file.
    
    Args:
        profile: The profile name (e.g., 'prod-long-term')
        access_key_id: The access key ID being deactivated
        secret_access_key: The secret access key being deactivated
    """
    logger.debug(f"Backing up deactivated key {access_key_id[:8]}... for profile {profile}")
    
    # Load or create the deactivated keys file
    deactivated = configparser.ConfigParser()
    if AWS_DEACTIVATED_KEYS_FILE.exists():
        deactivated.read(AWS_DEACTIVATED_KEYS_FILE)
    
    # Create a unique section name with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    section_name = f"{profile}_deactivated_{timestamp}"
    
    deactivated.add_section(section_name)
    deactivated.set(section_name, 'aws_access_key_id', access_key_id)
    deactivated.set(section_name, 'aws_secret_access_key', secret_access_key)
    deactivated.set(section_name, 'deactivated_at', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
    deactivated.set(section_name, 'original_profile', profile)
    
    with open(AWS_DEACTIVATED_KEYS_FILE, 'w') as f:
        deactivated.write(f)
    
    # Set restrictive permissions on the backup file (600 - owner read/write only)
    try:
        os.chmod(AWS_DEACTIVATED_KEYS_FILE, 0o600)
    except Exception as e:
        logger.debug(f"Could not set permissions on {AWS_DEACTIVATED_KEYS_FILE}: {e}")
    
    logger.info(f"Backed up deactivated key {access_key_id} to {AWS_DEACTIVATED_KEYS_FILE}")


def rotate_access_key(iam_client, long_term_profile: str, old_access_key_id: str) -> bool:
    """Rotate an access key by creating a new one, updating credentials, and deactivating the old one.
    
    Args:
        iam_client: Authenticated IAM client (using MFA session)
        long_term_profile: The long-term profile name (e.g., 'prod-long-term')
        old_access_key_id: The current access key ID to be rotated
    
    Returns:
        True if rotation was successful, False otherwise
    """
    display_name = get_display_name(long_term_profile)
    logger.info(f"Starting key rotation for profile {long_term_profile}")
    
    try:
        # Step 1: Get the current secret key for backup before creating new key
        credentials = load_credentials()
        old_secret_key = credentials.get(long_term_profile, 'aws_secret_access_key', fallback='')
        
        # Also preserve mfa_serial/aws_mfa_device if present
        mfa_serial = None
        for key in ['mfa_serial', 'aws_mfa_device']:
            if credentials.has_option(long_term_profile, key):
                mfa_serial = (key, credentials.get(long_term_profile, key))
                break
        
        # Step 2: Create new access key
        print_info("Creating new access key...")
        response = iam_client.create_access_key()
        new_key = response['AccessKey']
        new_access_key_id = new_key['AccessKeyId']
        new_secret_key = new_key['SecretAccessKey']
        
        logger.info(f"Created new access key {new_access_key_id[:8]}...")
        print_success(f"New access key created: {new_access_key_id}")
        
        # Step 3: Backup the old key
        print_info("Backing up old key to credentials.deactivated...")
        backup_deactivated_key(long_term_profile, old_access_key_id, old_secret_key)
        print_success(f"Old key backed up to {AWS_DEACTIVATED_KEYS_FILE}")
        
        # Step 4: Update credentials file with new key
        print_info("Updating credentials file with new key...")
        credentials = load_credentials()  # Reload to get fresh state
        
        if not credentials.has_section(long_term_profile):
            credentials.add_section(long_term_profile)
        
        credentials.set(long_term_profile, 'aws_access_key_id', new_access_key_id)
        credentials.set(long_term_profile, 'aws_secret_access_key', new_secret_key)
        
        # Preserve mfa_serial/aws_mfa_device
        if mfa_serial:
            credentials.set(long_term_profile, mfa_serial[0], mfa_serial[1])
        
        save_credentials(credentials)
        print_success(f"Credentials file updated for profile '{display_name}'")
        logger.info(f"Updated credentials file with new key {new_access_key_id[:8]}...")
        
        # Step 5: Deactivate the old key
        print_info("Deactivating old access key...")
        iam_client.update_access_key(AccessKeyId=old_access_key_id, Status='Inactive')
        print_success(f"Old key {old_access_key_id} has been deactivated")
        logger.info(f"Deactivated old access key {old_access_key_id}")
        
        print("")
        print_success(f"Key rotation complete for '{display_name}'!")
        print_info(f"New key: {new_access_key_id}")
        print_info(f"Old key: {old_access_key_id} (deactivated, backed up)")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        
        if error_code == 'LimitExceeded':
            print_error(f"Cannot create new key: AWS limit of 2 keys per user reached.")
            print_error("Please delete an existing inactive key first.")
        else:
            print_error(f"AWS Error during key rotation: {error_code} - {error_msg}")
        
        logger.error(f"Key rotation failed: {error_code} - {error_msg}")
        return False
        
    except Exception as e:
        print_error(f"Key rotation failed: {e}")
        logger.error(f"Key rotation failed: {e}")
        return False


def offer_key_rotation(iam_client, long_term_profile: str, access_key_id: str, age_days: int) -> bool:
    """Offer the user the option to rotate an expired or expiring key.
    
    Args:
        iam_client: Authenticated IAM client (using MFA session)
        long_term_profile: The long-term profile name (e.g., 'prod-long-term')
        access_key_id: The current access key ID
        age_days: The age of the key in days
    
    Returns:
        True if rotation was performed successfully, False otherwise
    """
    display_name = get_display_name(long_term_profile)
    
    print("")
    print(f"{Colors.YELLOW}{Colors.BOLD}═══════════════════════════════════════════════════════════{Colors.ENDC}")
    print(f"{Colors.YELLOW}{Colors.BOLD}  KEY ROTATION AVAILABLE{Colors.ENDC}")
    print(f"{Colors.YELLOW}{Colors.BOLD}═══════════════════════════════════════════════════════════{Colors.ENDC}")
    print("")
    print(f"  Profile: {display_name}")
    print(f"  Current key: {access_key_id}")
    print(f"  Key age: {age_days} days (limit: {AWS_KEY_EXPIRATION_DAYS} days)")
    print("")
    print("  This will:")
    print(f"    1. Create a new access key")
    print(f"    2. Update ~/.aws/credentials with the new key")
    print(f"    3. Deactivate the old key")
    print(f"    4. Backup the old key to ~/.aws/credentials.deactivated")
    print("")
    
    try:
        response = input(f"  {Colors.YELLOW}Do you want to rotate this key? (yes/no): {Colors.ENDC}").strip().lower()
        
        if response in ('yes', 'y'):
            print("")
            return rotate_access_key(iam_client, long_term_profile, access_key_id)
        else:
            print_info("Key rotation skipped.")
            return False
            
    except KeyboardInterrupt:
        print("")
        print_info("Key rotation cancelled.")
        return False


def check_key_age(credentials_data: Dict, long_term_profile: str) -> Optional[int]:
    """Check the age of the access key for a profile.
    
    Args:
        credentials_data: The fresh credentials from STS (AccessKeyId, SecretAccessKey, SessionToken)
        long_term_profile: The long-term profile name to get the key ID (e.g., 'prod-long-term')
    
    Uses the fresh MFA credentials directly to avoid boto3 caching issues.
    
    Returns:
        The age of the key in days, or None if it couldn't be determined.
    """
    logger.debug(f"Checking access key age using fresh credentials")
    
    try:
        # Create session with fresh credentials directly (bypasses file cache)
        session = boto3.Session(
            aws_access_key_id=credentials_data['AccessKeyId'],
            aws_secret_access_key=credentials_data['SecretAccessKey'],
            aws_session_token=credentials_data['SessionToken']
        )
        iam = session.client('iam', config=BOTO_CONFIG)
        
        # Get the access key ID from the long-term credentials file
        credentials = load_credentials()
        if not credentials.has_option(long_term_profile, 'aws_access_key_id'):
            logger.debug(f"No access key ID found in profile {long_term_profile}")
            return None
        
        access_key_id = credentials.get(long_term_profile, 'aws_access_key_id')
        
        # Get access key metadata
        response = iam.list_access_keys()
        all_keys = response.get('AccessKeyMetadata', [])
        
        # Warn if user has multiple keys and offer to manage them
        if len(all_keys) > 1:
            other_keys = [k for k in all_keys if k['AccessKeyId'] != access_key_id]
            print_warning(f"Multiple access keys detected! Only ONE key should be active.")
            print_warning(f"Current key in use: {access_key_id}")
            for key in other_keys:
                status = key.get('Status', 'Unknown')
                # Display "Deactivated" instead of AWS's "Inactive" for clarity
                display_status = "Deactivated" if status == "Inactive" else status
                key_id = key['AccessKeyId']
                print_warning(f"  → Extra key: {key_id} (Status: {display_status})")
            logger.warning(f"User has {len(all_keys)} access keys, other keys: {[k['AccessKeyId'] for k in other_keys]}")
            
            # Offer to manage extra keys
            for key in other_keys:
                key_id = key['AccessKeyId']
                status = key.get('Status', 'Unknown')
                
                print("")
                print_warning(f"Do you want to manage key {key_id}?")
                print(f"  Type 'deactivate' to deactivate the key")
                print(f"  Type 'delete' to permanently delete the key")
                print(f"  Press Enter to skip")
                
                try:
                    action = input("  Your choice: ").strip().lower()
                    
                    if action == "deactivate":
                        if status == "Inactive":
                            print_info(f"Key {key_id} is already deactivated.")
                        else:
                            confirm = input(f"  Type 'deactivate' again to confirm: ").strip().lower()
                            if confirm == "deactivate":
                                iam.update_access_key(AccessKeyId=key_id, Status='Inactive')
                                print_success(f"Key {key_id} has been deactivated.")
                                logger.info(f"Deactivated access key {key_id}")
                            else:
                                print_info("Deactivation cancelled.")
                    
                    elif action == "delete":
                        print_warning(f"⚠ WARNING: This will PERMANENTLY delete key {key_id}!")
                        confirm = input(f"  Type 'delete' again to confirm: ").strip().lower()
                        if confirm == "delete":
                            iam.delete_access_key(AccessKeyId=key_id)
                            print_success(f"Key {key_id} has been deleted.")
                            logger.info(f"Deleted access key {key_id}")
                        else:
                            print_info("Deletion cancelled.")
                    
                    elif action == "":
                        print_info("Skipped.")
                    
                    else:
                        print_info(f"Unknown action '{action}'. Skipped.")
                
                except KeyboardInterrupt:
                    print("")
                    print_info("Key management cancelled.")
                    break
                except Exception as e:
                    print_error(f"Failed to manage key: {e}")
                    logger.error(f"Failed to manage key {key_id}: {e}")
        
        for key_metadata in all_keys:
            if key_metadata['AccessKeyId'] == access_key_id:
                create_date = key_metadata['CreateDate']
                if create_date.tzinfo is None:
                    create_date = create_date.replace(tzinfo=timezone.utc)
                
                age_days = (datetime.now(timezone.utc) - create_date).days
                days_until_expiration = AWS_KEY_EXPIRATION_DAYS - age_days
                logger.debug(f"Access key {access_key_id[:8]}... created {create_date}, age: {age_days} days, expires in {days_until_expiration} days")
                
                # Display the key age with rotation warning
                if age_days >= AWS_KEY_EXPIRATION_DAYS:
                    print_warning(f"Access key age: {age_days} days - KEY ROTATION REQUIRED (exceeded {AWS_KEY_EXPIRATION_DAYS} days)")
                    # Offer key rotation for expired keys
                    offer_key_rotation(iam, long_term_profile, access_key_id, age_days)
                elif days_until_expiration <= AWS_KEY_WARNING_DAYS:
                    print_warning(f"Access key age: {age_days} days - KEY ROTATION RECOMMENDED (expires in {days_until_expiration} days)")
                    # Offer key rotation for keys expiring soon
                    offer_key_rotation(iam, long_term_profile, access_key_id, age_days)
                else:
                    print_info(f"Access key age: {age_days} days")
                
                return age_days
        
        logger.debug(f"Access key {access_key_id[:8]}... not found in IAM response")
        return None
        
    except Exception as e:
        logger.debug(f"Could not check key age: {e}")
        print_warning(f"Could not check key age: {e}")
        return None


def display_session_info(credentials_data: Dict):
    """Display user and account information using the fresh MFA credentials.
    
    Args:
        credentials_data: The fresh credentials from STS (AccessKeyId, SecretAccessKey, SessionToken)
    
    Uses the fresh credentials directly to avoid boto3 caching issues.
    """
    logger.debug(f"Fetching session info using fresh credentials")
    
    try:
        # Create session with fresh credentials directly (bypasses file cache)
        session = boto3.Session(
            aws_access_key_id=credentials_data['AccessKeyId'],
            aws_secret_access_key=credentials_data['SecretAccessKey'],
            aws_session_token=credentials_data['SessionToken']
        )
        sts = session.client('sts', config=BOTO_CONFIG)
        
        identity = sts.get_caller_identity()
        account_id = identity.get('Account', 'Unknown')
        arn = identity.get('Arn', '')
        
        # Extract username from ARN (arn:aws:sts::123456789012:assumed-role/... or arn:aws:iam::...)
        username = 'Unknown'
        if ':user/' in arn:
            username = arn.split(':user/')[-1]
        elif ':assumed-role/' in arn:
            # For assumed role, format is: assumed-role/role-name/session-name
            username = arn.split(':assumed-role/')[-1].split('/')[0]
        elif 'arn:aws:sts::' in arn:
            # Federated user format
            parts = arn.split('/')
            if len(parts) > 1:
                username = parts[-1]
        
        print_info(f"User: {username} | Account: {account_id}")
        logger.info(f"Session info - User: {username}, Account: {account_id}, ARN: {arn}")
        
    except Exception as e:
        logger.debug(f"Could not fetch session info: {e}")
        print_warning(f"Could not fetch session info: {e}")


def check_session_valid(profile: str) -> Tuple[bool, Optional[datetime]]:
    """Check if an MFA session is still valid.
    
    Args:
        profile: The long-term profile name (e.g., 'prod-long-term')
    
    The MFA session is stored under the display name (e.g., 'prod').
    Only checks local expiration timestamp - no AWS API calls.
    
    Returns:
        Tuple of (is_valid, expiration_datetime)
        - (True, datetime) - session valid until datetime
        - (False, datetime) - session expired at datetime  
        - (False, None) - never logged in (no expiration field)
    """
    mfa_profile = get_display_name(profile)
    logger.debug(f"Checking session validity for {mfa_profile}")
    credentials = load_credentials()
    
    # Check if expiration field exists (only set by this tool after successful MFA login)
    if not credentials.has_section(mfa_profile) or not credentials.has_option(mfa_profile, 'expiration'):
        logger.debug(f"No expiration found for {mfa_profile} - never logged in with this tool")
        return False, None
    
    try:
        expiration_str = credentials.get(mfa_profile, 'expiration')
        
        # Parse aws-mfa compatible format: YYYY-MM-DD HH:MM:SS
        expiration = datetime.strptime(expiration_str, '%Y-%m-%d %H:%M:%S')
        expiration = expiration.replace(tzinfo=timezone.utc)
        
        now = datetime.now(timezone.utc)
        
        if expiration > now:
            logger.debug(f"Session valid until {expiration}")
            return True, expiration
        logger.debug(f"Session expired at {expiration}")
        return False, expiration
    except Exception as e:
        logger.debug(f"Failed to parse expiration: {e}")
        return False, None


def get_session_token(profile: str, mfa_serial: str, mfa_token: str, 
                      duration: int = DEFAULT_SESSION_DURATION) -> Optional[Dict]:
    """Get temporary session credentials using MFA."""
    logger.debug(f"Requesting session token for profile={profile}, mfa_serial={mfa_serial}, duration={duration}s")
    try:
        session = boto3.Session(profile_name=profile)
        sts = session.client('sts', config=BOTO_CONFIG)
        
        response = sts.get_session_token(
            DurationSeconds=duration,
            SerialNumber=mfa_serial,
            TokenCode=mfa_token
        )
        
        logger.debug(f"Session token obtained successfully, expires: {response['Credentials']['Expiration']}")
        return response['Credentials']
    except ClientError as e:
        error_code = e.response['Error']['Code']
        logger.debug(f"ClientError: {error_code} - {e}")
        # Silent fail for retryable errors - error shown after all attempts
        if error_code in ('AccessDenied', 'InvalidIdentityToken'):
            logger.debug(f"MFA authentication failed: {error_code}")
        else:
            print_error(f"AWS Error: {e}")
        return None
    except Exception as e:
        logger.debug(f"Exception getting session token: {e}")
        print_error(f"Error getting session token: {e}")
        return None


def save_mfa_credentials(profile: str, credentials_data: Dict):
    """Save MFA session credentials to a new profile.
    
    Args:
        profile: The long-term profile name (e.g., 'prod-long-term')
        credentials_data: The temporary credentials from STS
    
    The MFA session is saved under the display name (e.g., 'prod').
    """
    credentials = load_credentials()
    mfa_profile = get_display_name(profile)
    
    if not credentials.has_section(mfa_profile):
        credentials.add_section(mfa_profile)
    
    credentials.set(mfa_profile, 'aws_access_key_id', credentials_data['AccessKeyId'])
    credentials.set(mfa_profile, 'aws_secret_access_key', credentials_data['SecretAccessKey'])
    credentials.set(mfa_profile, 'aws_session_token', credentials_data['SessionToken'])
    # Use aws-mfa compatible format: YYYY-MM-DD HH:MM:SS
    expiration_utc = credentials_data['Expiration'].astimezone(timezone.utc)
    credentials.set(mfa_profile, 'expiration', expiration_utc.strftime('%Y-%m-%d %H:%M:%S'))
    
    save_credentials(credentials)
    return mfa_profile


def authenticate_profile(profile: str, force: bool = False, 
                         duration: int = DEFAULT_SESSION_DURATION) -> bool:
    """Authenticate a single profile with MFA.
    
    Args:
        profile: The long-term profile name (e.g., 'prod-long-term')
    
    Displays the short name (e.g., 'prod') and creates MFA session under that name.
    """
    display_name = get_display_name(profile)
    logger.info(f"Authenticating profile: {profile} -> {display_name} (force={force}, duration={duration}s)")
    print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.CYAN}Profile: {display_name}{Colors.ENDC}")
    print(f"{'='*60}")
    
    is_valid, expiration = check_session_valid(profile)
    if is_valid and not force:
        if expiration:
            remaining = expiration - datetime.now(timezone.utc)
            hours, remainder = divmod(int(remaining.total_seconds()), 3600)
            minutes = remainder // 60
            print_success(f"Session still valid for {hours}h {minutes}m")
        else:
            print_success(f"Session is valid")
        return True
    
    mfa_serial = get_mfa_serial(profile)
    if not mfa_serial:
        print_warning(f"No MFA device found for profile '{display_name}'")
        mfa_serial = input(f"Enter MFA ARN (arn:aws:iam::ACCOUNT:mfa/USER): ").strip()
        if not mfa_serial:
            print_error("MFA ARN is required")
            return False
    
    for attempt in range(1, MFA_MAX_ATTEMPTS + 1):
        # Get and validate MFA token format before attempting login
        while True:
            prompt = f"{Colors.YELLOW}Enter MFA token for {display_name}: {Colors.ENDC}"
            if attempt > 1:
                prompt = f"{Colors.YELLOW}Retry MFA token for {display_name} ({attempt}/{MFA_MAX_ATTEMPTS}): {Colors.ENDC}"
            
            mfa_token = input(prompt).strip()
            
            if not mfa_token:
                print_error("MFA token is required")
                continue
            
            if not mfa_token.isdigit() or len(mfa_token) != MFA_TOKEN_LENGTH:
                print_error(f"MFA token must be {MFA_TOKEN_LENGTH} digits")
                continue
            
            break
        
        hours, remainder = divmod(duration, 3600)
        minutes = remainder // 60
        print_info(f"Requesting session token for {hours}h {minutes}m...")
        creds = get_session_token(profile, mfa_serial, mfa_token, duration)
        
        if creds:
            break
        
        # Authentication failed - loop will retry or exit
        if attempt >= MFA_MAX_ATTEMPTS:
            print_error(f"Authentication failed after {MFA_MAX_ATTEMPTS} attempts. Check MFA token and permissions.")
            return False
    
    if creds:
        mfa_profile = save_mfa_credentials(profile, creds)
        print_success(f"Authentication successful! (use profile: {mfa_profile})")
        
        # Display user info using fresh credentials (avoids boto3 caching issues)
        display_session_info(creds)
        
        # Check and display access key age using fresh credentials
        check_key_age(creds, profile)
        
        return True
    
    return False


def list_profiles():
    """List all available profiles and their status.
    
    Displays profile names without the -long-term suffix.
    """
    credentials = load_credentials()
    long_term = get_long_term_profiles(credentials)
    
    print(f"\n{Colors.BOLD}Available Profiles:{Colors.ENDC}")
    print("-" * 50)
    
    if not long_term:
        print_warning("No long-term credential profiles found (profiles must end with '-long-term')")
        return
    
    for profile in sorted(long_term):
        display_name = get_display_name(profile)
        is_valid, expiration = check_session_valid(profile)
        
        status = ""
        if is_valid and expiration:
            remaining = expiration - datetime.now(timezone.utc)
            hours, remainder = divmod(int(remaining.total_seconds()), 3600)
            minutes = remainder // 60
            status = f"{Colors.GREEN}[MFA Valid: {hours}h {minutes}m remaining]{Colors.ENDC}"
        elif not is_valid and expiration:
            # Has expiration but it's in the past = expired
            status = f"{Colors.RED}[MFA session expired]{Colors.ENDC}"
        else:
            # No expiration field = never logged in with this tool
            status = f"{Colors.YELLOW}[Never logged in]{Colors.ENDC}"
        
        print(f"  • {display_name} {status}")
    
    print()


def validate_profiles(profiles: List[str], credentials: configparser.ConfigParser) -> List[str]:
    """Validate that specified profiles exist.
    
    Accepts both display names (e.g., 'prod') and long-term names (e.g., 'prod-long-term').
    Returns the long-term profile names.
    """
    long_term = get_long_term_profiles(credentials)
    # Create a mapping from display names to long-term names
    display_to_long_term = {get_display_name(p): p for p in long_term}
    valid = []
    
    for profile in profiles:
        # Check if user provided the display name or the full long-term name
        if profile in long_term:
            valid.append(profile)
        elif profile in display_to_long_term:
            valid.append(display_to_long_term[profile])
        else:
            print_warning(f"Profile '{profile}' not found (looking for '{profile}-long-term' in credentials)")
    
    return valid


def main():
    parser = argparse.ArgumentParser(
        description='AWS MFA Authentication Manager - Authenticate AWS profiles with MFA tokens',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                    List all profiles and their MFA status
  %(prog)s --profile prod            Authenticate single profile
  %(prog)s --profile dev,prod,stage  Authenticate multiple profiles
  %(prog)s --all                     Authenticate all long-term profiles
  %(prog)s --all --force             Force re-authentication even if valid
  %(prog)s --profile prod --duration 3600  1-hour session
        """
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-p', '--profile',
        type=str,
        help='Profile name(s) to authenticate (comma-separated)'
    )
    group.add_argument(
        '-a', '--all',
        action='store_true',
        help='Authenticate all long-term credential profiles'
    )
    group.add_argument(
        '-l', '--list',
        action='store_true',
        help='List all profiles and their MFA status'
    )
    
    parser.add_argument(
        '-f', '--force',
        action='store_true',
        help='Force re-authentication even if session is still valid'
    )
    parser.add_argument(
        '-d', '--duration',
        type=int,
        default=DEFAULT_SESSION_DURATION,
        help=f'Session duration in seconds (default: {DEFAULT_SESSION_DURATION})'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Minimal output'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    args = parser.parse_args()
    
    # Initialize logging
    setup_logging(debug=args.debug)
    logger.info("AWS MFA Login started")
    logger.debug(f"Arguments: {vars(args)}")
    
    if not args.quiet:
        print_banner()
    
    if not AWS_CREDENTIALS_FILE.exists():
        print_error(f"AWS credentials file not found: {AWS_CREDENTIALS_FILE}")
        sys.exit(1)
    
    credentials = load_credentials()
    
    if args.list:
        list_profiles()
        sys.exit(0)
    
    if args.all:
        profiles = get_long_term_profiles(credentials)
        if not profiles:
            print_error("No long-term credential profiles found")
            sys.exit(1)
        print_info(f"Found {len(profiles)} profile(s) to authenticate")
    elif args.profile:
        profiles = [p.strip() for p in args.profile.split(',')]
        profiles = validate_profiles(profiles, credentials)
        if not profiles:
            print_error("No valid profiles to authenticate")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)
    
    success_count = 0
    fail_count = 0
    skip_count = 0
    
    for profile in profiles:
        try:
            result = authenticate_profile(profile, args.force, args.duration)
            if result:
                is_valid, _ = check_session_valid(profile)
                if is_valid and not args.force:
                    skip_count += 1
                else:
                    success_count += 1
            else:
                fail_count += 1
        except KeyboardInterrupt:
            print_warning("\nAuthentication cancelled by user")
            break
        except Exception as e:
            print_error(f"Error authenticating {profile}: {e}")
            fail_count += 1
    
    if args.debug:
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}Summary:{Colors.ENDC}")
        print(f"  {Colors.GREEN}Authenticated: {success_count}{Colors.ENDC}")
        print(f"  {Colors.YELLOW}Skipped (valid): {skip_count}{Colors.ENDC}")
        print(f"  {Colors.RED}Failed: {fail_count}{Colors.ENDC}")
        print(f"{'='*60}\n")
    
    logger.info(f"Completed - Authenticated: {success_count}, Skipped: {skip_count}, Failed: {fail_count}")
    
    if fail_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()