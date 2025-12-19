# AWS MFA Authentication Manager

A cross-platform Python CLI tool that simplifies managing MFA authentication across multiple AWS profiles. Authenticate all your AWS profiles with a single command. Supports macOS, Linux, and Windows.

## Features

- 🔐 **Multi-profile support** - Authenticate one, multiple, or all profiles at once
- ⏱️ **Session tracking** - Automatically skips profiles with valid sessions
- 🔍 **Config-based MFA** - Reads MFA device ARN from config or credentials file
- 📁 **Clean organization** - Long-term keys in `{profile}-long-term`, MFA sessions in `{profile}`
- 🎨 **Beautiful CLI** - Color-coded output with clear status indicators
- ⚡ **Fast** - Only prompts for MFA when actually needed
- 📝 **Logging** - Automatic logging to `output/` directory with daily log files
- 🐛 **Debug mode** - Verbose output for troubleshooting with `--debug`
- 🔧 **Environment file support** - Load credentials from `.env` file via python-dotenv
- 🔑 **Key age monitoring** - Displays access key age and warns when rotation is needed
- 🔄 **Automatic key rotation** - Offers to create new keys, update credentials, and deactivate old keys
- 🗑️ **Key management** - Interactive prompts to deactivate or delete extra access keys
- 👤 **User info display** - Shows IAM username and account ID after successful login

## Requirements

- Python 3.7+
- macOS, Linux, or Windows
- boto3
- python-dotenv (optional, for `.env` file support)

## Installation

### Quick Install

```bash
# Clone or download the script
curl -O https://raw.githubusercontent.com/yadox666/aws_mfa_login/main/aws_mfa_login.py

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x aws_mfa_login.py

# Optional: Move to PATH for global access
sudo mv aws_mfa_login.py /usr/local/bin/aws-mfa
```

### From Source

```bash
git clone https://github.com/yadox666/aws_mfa_login.git
cd aws_mfa_login
pip3 install -r requirements.txt
chmod +x aws_mfa_login.py
```

## Getting Started (For New Users)

If you're new to AWS CLI, follow these steps to set up your credentials and MFA.

### Step 1: Create AWS Access Keys

1. Log in to the [AWS Console](https://console.aws.amazon.com/)
2. Click your username in the top-right corner → **Security credentials**
3. Scroll to **Access keys** section
4. Click **Create access key**
5. Select **Command Line Interface (CLI)** as the use case
6. Check the confirmation box and click **Next**
7. (Optional) Add a description tag
8. Click **Create access key**
9. **Important**: Copy both the **Access key ID** and **Secret access key** - the secret is only shown once!

### Step 2: Create the Credentials File

Create the AWS credentials file on your system:

**macOS/Linux:**
```bash
mkdir -p ~/.aws
touch ~/.aws/credentials
chmod 600 ~/.aws/credentials
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.aws"
New-Item -ItemType File -Force -Path "$env:USERPROFILE\.aws\credentials"
```

Edit the file and add your credentials:

```ini
[default-long-term]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Or use the AWS CLI to configure:
```bash
aws configure --profile default-long-term
```

### Step 3: Find Your MFA ARN

1. Log in to the [AWS Console](https://console.aws.amazon.com/)
2. Click your username in the top-right corner → **Security credentials**
3. Scroll to **Multi-factor authentication (MFA)** section
4. Your MFA device ARN looks like: `arn:aws:iam::123456789012:mfa/your-username`
5. Copy this ARN

> **Don't have MFA set up?** Click **Assign MFA device** and follow the prompts to set up an authenticator app.

### Step 4: Add MFA ARN

You should add the MFA ARN to the **credentials file**.

**Add to credentials file**:

```ini
# ~/.aws/credentials
[default-long-term]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
mfa_serial = arn:aws:iam::123456789012:mfa/your-username
```

```ini
[default-long-term]
region = us-east-1
mfa_serial = arn:aws:iam::123456789012:mfa/your-username

[profile prod-long-term]
region = us-west-2
mfa_serial = arn:aws:iam::123456789012:mfa/your-username
```

> **Note**: For non-default profiles in the config file, use `[profile name]` format.

### Step 5: Test It

```bash
# List your profiles (shows 'default' not 'default-long-term')
python aws_mfa_login.py --list

# Authenticate (use short name 'default', not 'default-long-term')
python aws_mfa_login.py --profile default
```

---

## Configuration

### AWS Credentials File

The script reads your `~/.aws/credentials` file and identifies long-term credential profiles (those with `aws_access_key_id` and `aws_secret_access_key` but without `aws_session_token`).

You can also include the `mfa_serial` directly in the credentials file:

```ini
# ~/.aws/credentials

[default-long-term]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
mfa_serial = arn:aws:iam::123456789012:mfa/username

[prod-long-term]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
mfa_serial = arn:aws:iam::123456789012:mfa/prod-user

[dev-long-term]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
mfa_serial = arn:aws:iam::987654321098:mfa/dev-user
```

### MFA Serial Configuration

The script looks for the MFA device ARN in local configuration files only:

1. **Config file** (`~/.aws/config`) - checked first
2. **Credentials file** (`~/.aws/credentials`) - checked second

Supported field names (for aws-mfa tool compatibility):
- `mfa_serial` - standard name
- `aws_mfa_device` - aws-mfa tool format

If not found, you'll be prompted to enter it manually.

> **Security note**: The script does NOT query AWS APIs before MFA authentication to avoid generating CloudTrail events with long-term credentials. All AWS API calls are made only after successful MFA login using the temporary session.

### Environment File (Optional)

You can also load AWS credentials from a `.env` file in the current directory. Copy `.env.example` to `.env` and configure:

```ini
# .env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_MFA_SERIAL=arn:aws:iam::123456789012:mfa/username
AWS_KEY_EXPIRATION_DAYS=365
```

> **Note**: The `.env` file is automatically ignored by git. Never commit credentials to version control.

#### .env vs ~/.aws/credentials

| Feature | `.env` file | `~/.aws/credentials` |
|---------|-------------|---------------------|
| Multiple profiles | ❌ No (single credential only) | ✅ Yes |
| Project-specific | ✅ Yes (per directory) | ❌ No (global) |
| AWS standard | ❌ No | ✅ Yes |

**When to use `.env`:**
- Single default credential for a specific project
- Overriding region or other settings per project
- Quick testing without modifying global AWS config

**When to use `~/.aws/credentials`:**
- Managing multiple AWS accounts/profiles
- Standard AWS CLI workflow
- Using this tool's multi-profile authentication features

**For multiple profiles**, always use `~/.aws/credentials` - it's the AWS standard and supports the full functionality of this tool. The `.env` file is best suited for project-specific overrides or single-credential scenarios.

### Access Key Rotation Reminder

After successful authentication, the script displays your access key age and warns when rotation is needed:

```
✓ Authentication successful! (use profile: prod)
ℹ User: your-username | Account: 123456789012
ℹ Access key age: 245 days
```

Warning starts **30 days before expiration**:

```
⚠ Access key age: 340 days - KEY ROTATION RECOMMENDED (expires in 25 days)
```

If the key has **exceeded the threshold**:

```
⚠ Access key age: 412 days - KEY ROTATION REQUIRED (exceeded 365 days)
```

### Automatic Key Rotation

When a key is expired or expiring soon, the script offers to automatically rotate it:

```
⚠ Access key age: 412 days - KEY ROTATION REQUIRED (exceeded 365 days)

═══════════════════════════════════════════════════════════
  KEY ROTATION AVAILABLE
═══════════════════════════════════════════════════════════

  Profile: prod
  Current key: AKIAIOSFODNN7EXAMPLE
  Key age: 412 days (limit: 365 days)

  This will:
    1. Create a new access key
    2. Update ~/.aws/credentials with the new key
    3. Deactivate the old key
    4. Backup the old key to ~/.aws/credentials.deactivated

  Do you want to rotate this key? (yes/no): yes

ℹ Creating new access key...
✓ New access key created: AKIAI44QH8DHBEXAMPLE
ℹ Backing up old key to credentials.deactivated...
✓ Old key backed up to /Users/you/.aws/credentials.deactivated
ℹ Updating credentials file with new key...
✓ Credentials file updated for profile 'prod'
ℹ Deactivating old access key...
✓ Old key AKIAIOSFODNN7EXAMPLE has been deactivated

✓ Key rotation complete for 'prod'!
ℹ New key: AKIAI44QH8DHBEXAMPLE
ℹ Old key: AKIAIOSFODNN7EXAMPLE (deactivated, backed up)
```

**What happens during rotation:**

1. **New key created** - A new access key is generated via IAM
2. **Credentials updated** - `~/.aws/credentials` is updated with the new key (MFA serial preserved)
3. **Old key deactivated** - The previous key is set to Inactive status (not deleted)
4. **Backup created** - The old credentials are saved to `~/.aws/credentials.deactivated` with:
   - Timestamped section name for history tracking
   - Original profile name and deactivation timestamp
   - File permissions set to 600 (owner read/write only)

**Example backup file** (`~/.aws/credentials.deactivated`):

```ini
[prod-long-term_deactivated_20251219_143052]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
deactivated_at = 2025-12-19 14:30:52 UTC
original_profile = prod-long-term
```

**Note:** The old key is only deactivated, not deleted. This allows you to:
- Revert if something goes wrong (reactivate via AWS Console)
- Have a recovery option if the new key has issues
- Permanently delete old keys at your convenience

**Multiple keys warning** - If more than one access key exists, the script offers to manage them:

```
⚠ Multiple access keys detected! Only ONE key should be active.
⚠ Current key in use: AKIAIOSFODNN7EXAMPLE
⚠   → Extra key: AKIAI44QH8DHBEXAMPLE (Status: Active)

⚠ Do you want to manage key AKIAI44QH8DHBEXAMPLE?
  Type 'deactivate' to deactivate the key
  Type 'delete' to permanently delete the key
  Press Enter to skip
  Your choice: delete
⚠ WARNING: This will PERMANENTLY delete key AKIAI44QH8DHBEXAMPLE!
  Type 'delete' again to confirm: delete
✓ Key AKIAI44QH8DHBEXAMPLE has been deleted.
```

**Configure the threshold** via environment variable or `.env` file:

```bash
# Default is 365 days
export AWS_KEY_EXPIRATION_DAYS=180
```

### Security Warnings Explained

The script provides several security warnings to help you maintain AWS security best practices:

#### 🔄 Key Rotation Warnings

| Warning | Meaning |
|---------|---------|
| `ℹ Access key age: X days` | Informational - key is within acceptable age |
| `⚠ KEY ROTATION RECOMMENDED (expires in X days)` | Key will exceed threshold in 30 days or less |
| `⚠ KEY ROTATION REQUIRED (exceeded X days)` | Key has exceeded the configured threshold |

**Why rotate access keys?**

- **Limit exposure window**: If a key is compromised, regular rotation limits how long an attacker can use it
- **Compliance requirements**: Many security frameworks (SOC 2, PCI-DSS, HIPAA) require periodic credential rotation
- **Reduce risk from forgotten keys**: Old keys may have been shared, stored insecurely, or forgotten in old systems
- **AWS best practice**: AWS recommends rotating keys every 90 days for sensitive environments

**How to rotate:**

**Option 1: Automatic (recommended)** - Use this tool's built-in rotation feature:
- When a key is expired/expiring, the tool will offer to rotate it automatically
- This creates a new key, updates credentials, deactivates the old key, and creates a backup

**Option 2: Manual** - Rotate via AWS Console:
1. Create a new access key in AWS Console → IAM → Users → Security credentials
2. Update your `~/.aws/credentials` file with the new key
3. Test that the new key works
4. Delete the old key from AWS Console

#### 🔑 Multiple Keys Warning

```
⚠ Multiple access keys detected! Only ONE key should be active.
⚠ Current key in use: AKIAIOSFODNN7EXAMPLE
⚠   → Extra key: AKIAI44QH8DHBEXAMPLE (Status: Active)

⚠ Do you want to manage key AKIAI44QH8DHBEXAMPLE?
  Type 'deactivate' to deactivate the key
  Type 'delete' to permanently delete the key
  Press Enter to skip
```

The script interactively offers to **deactivate** or **delete** extra keys. Both actions require typing the command twice for confirmation.

**Why only one key?**

- **Simplified management**: One key is easier to track, rotate, and audit
- **Clear accountability**: Multiple keys make it harder to determine which key is used where
- **Reduced attack surface**: Each additional key is another potential point of compromise
- **Easier incident response**: If a breach occurs, you know exactly which key to revoke
- **AWS allows maximum 2 keys**: The limit exists only to facilitate rotation, not for parallel use

**When are two keys acceptable?**
Only temporarily during key rotation:
1. Create new key (now you have 2)
2. Update all systems to use new key
3. Verify everything works
4. Delete old key (back to 1)

#### 🛡️ Why MFA Matters

This tool exists because MFA (Multi-Factor Authentication) significantly improves security:

- **Defense in depth**: Even if your access key is stolen, attackers can't use it without your MFA device
- **Session-based access**: MFA sessions expire (default 12 hours), limiting the window of access
- **Compliance**: Many organizations require MFA for all AWS access
- **AWS recommendation**: AWS strongly recommends MFA for all IAM users, especially those with console access

## Usage

### List All Profiles

View all available profiles and their current MFA session status:

```bash
./aws_mfa_login.py --list
# or
./aws_mfa_login.py -l
```

Output:
```
Available Profiles:
--------------------------------------------------
  • default [Never logged in]
  • dev [MFA Valid: 8h 42m remaining]
  • prod [MFA session expired]
  • staging [Never logged in]
```

### Authenticate Single Profile

```bash
./aws_mfa_login.py --profile prod
# or
./aws_mfa_login.py -p prod
```

### Authenticate Multiple Profiles

```bash
./aws_mfa_login.py --profile dev,prod,staging
# or
./aws_mfa_login.py -p dev,prod,staging
```

### Authenticate All Profiles

```bash
./aws_mfa_login.py --all
# or
./aws_mfa_login.py -a
```

### Force Re-authentication

Re-authenticate even if sessions are still valid:

```bash
./aws_mfa_login.py --all --force
# or
./aws_mfa_login.py -a -f
```

### Custom Session Duration

Set session duration in seconds (default: 43200 = 12 hours):

```bash
# 1 hour session
./aws_mfa_login.py --profile prod --duration 3600

# 24 hour session (if allowed by IAM policy)
./aws_mfa_login.py --profile prod --duration 86400
```

### Quiet Mode

Minimal output:

```bash
./aws_mfa_login.py --all --quiet
```

### Debug Mode

Enable verbose logging to console and log file for troubleshooting:

```bash
./aws_mfa_login.py --profile prod --debug
```

## Logging

All operations are logged to the `output/` directory with daily log files (`aws_mfa_YYYYMMDD.log`).

- **Normal mode**: Logs INFO level and above to file only
- **Debug mode** (`--debug`): Logs DEBUG level to both console and file

View recent logs:

```bash
cat output/aws_mfa_$(date +%Y%m%d).log
```

## Command Reference

```
usage: aws_mfa_login.py [-h] [-p PROFILE | -a | -l] [-f] [-d DURATION] [-q] [--debug]

AWS MFA Authentication Manager - Authenticate AWS profiles with MFA tokens

optional arguments:
  -h, --help            show this help message and exit
  -p, --profile PROFILE Profile name(s) to authenticate (comma-separated)
  -a, --all             Authenticate all long-term credential profiles
  -l, --list            List all profiles and their MFA status
  -f, --force           Force re-authentication even if session is still valid
  -d, --duration DURATION
                        Session duration in seconds (default: 43200)
  -q, --quiet           Minimal output
  --debug               Enable debug mode with verbose logging

Examples:
  aws_mfa_login.py --list                    List all profiles and their MFA status
  aws_mfa_login.py --profile prod            Authenticate single profile
  aws_mfa_login.py --profile dev,prod        Authenticate multiple profiles
  aws_mfa_login.py --all                     Authenticate all long-term profiles
  aws_mfa_login.py --all --force             Force re-authentication even if valid
  aws_mfa_login.py --profile prod --duration 3600  1-hour session
  aws_mfa_login.py --profile prod --debug    Authenticate with debug output
```

## How It Works

1. **Discovery**: Scans `~/.aws/credentials` for profiles ending with `-long-term`
2. **Display**: Shows profiles without the `-long-term` suffix for cleaner output
3. **Validation**: Checks if existing MFA sessions are still valid (uses local expiration timestamp)
4. **MFA Lookup**: Reads MFA device ARN from local config/credentials files only (no AWS API calls)
5. **Authentication**: Prompts for MFA token and calls `sts:GetSessionToken`
6. **Storage**: Saves temporary credentials under the short profile name (e.g., `[prod]`)
7. **Post-auth checks**: Displays user info, key age, offers key rotation if needed, and manages extra keys (using MFA session)

### Profile Naming Convention

The script uses a clear naming convention to separate long-term credentials from temporary MFA sessions:

| In Credentials File | Displayed As | MFA Session Created |
|---------------------|--------------|---------------------|
| `[default-long-term]` | `default` | `[default]` |
| `[prod-long-term]` | `prod` | `[prod]` |
| `[dev-long-term]` | `dev` | `[dev]` |

**How it works:**
1. Store your long-term AWS credentials in profiles ending with `-long-term`
2. The script displays and accepts the short name (without `-long-term`)
3. MFA temporary credentials are saved under the short name

This keeps your credentials file organized:
- `[prod-long-term]` - Your permanent IAM access keys (never expires)
- `[prod]` - Temporary MFA session credentials (expires after session duration)

### Using MFA Profiles

After authentication, use the short profile name (without `-long-term`) in your commands:

```bash
# AWS CLI - verify identity (works for any user)
aws sts get-caller-identity --profile prod

# Environment variable
export AWS_PROFILE=prod

# Boto3 Python
session = boto3.Session(profile_name='prod')
```

## Example Session

```
╔═══════════════════════════════════════════════════════════╗
║           AWS MFA Authentication Manager                  ║
║            macOS · Linux · Windows                        ║
╚═══════════════════════════════════════════════════════════╝

ℹ Found 3 profile(s) to authenticate

============================================================
Profile: default
============================================================
Enter MFA token for default: 123456
ℹ Requesting session token for 12 hours, 0 minutes...
✓ Authentication successful! (use profile: default)
ℹ User: admin | Account: 111111111111
ℹ Access key age: 87 days

============================================================
Profile: dev
============================================================
✓ Session still valid for 8h 42m

============================================================
Profile: prod
============================================================
Enter MFA token for prod: 654321
ℹ Requesting session token for 12 hours, 0 minutes...
✓ Authentication successful! (use profile: prod)
ℹ User: prod-user | Account: 222222222222
⚠ Access key age: 350 days - KEY ROTATION RECOMMENDED (expires in 15 days)
```

## Troubleshooting

### "No MFA device found for profile"

The script couldn't find the MFA device ARN. Solutions:

1. Add `mfa_serial` to your credentials or config file:
   ```ini
   # In ~/.aws/credentials
   [myprofile-long-term]
   aws_access_key_id = AKIA...
   aws_secret_access_key = ...
   mfa_serial = arn:aws:iam::ACCOUNT_ID:mfa/USERNAME
   ```

2. Ensure the profile has IAM permissions to call `iam:GetUser` and `iam:ListMFADevices`

3. Enter the MFA ARN manually when prompted

### "Access denied"

- Verify the MFA token is correct (6 digits)
- Check that the IAM user has permission to call `sts:GetSessionToken`
- Ensure the MFA device is properly configured in IAM

### "Invalid MFA token"

- MFA tokens are time-sensitive; ensure your device clock is synchronized
- Wait for a new token if you just used one (tokens are single-use)

### Credentials file not found

Ensure you have AWS credentials configured:

```bash
aws configure --profile myprofile-long-term
```

> **Note**: Profile names in the credentials file must end with `-long-term` for the script to recognize them.

## Security Considerations

- Long-term credentials remain in `~/.aws/credentials` (unchanged)
- Temporary credentials are stored alongside with expiration tracking
- Session tokens are valid for the specified duration (default 12 hours)
- Consider using shorter durations for sensitive accounts

## Integration with Shell

Add an alias to your `~/.zshrc` or `~/.bashrc`:

```bash
# Authenticate all AWS profiles
alias aws-auth='aws_mfa_login.py --all'

# Quick auth for specific profile
alias aws-auth-prod='aws_mfa_login.py -p prod'

# List profile status
alias aws-status='aws_mfa_login.py --list'
```

## AWS Administrator Guide: Enforcing MFA

For AWS administrators who want to enforce MFA for all human users in their organization.

### MFA Enforcement IAM Policy

Attach this policy to IAM users or groups to enforce MFA. Users without MFA can only:
- View their own account information
- Set up their MFA device
- Change their password

Once MFA is configured, they get full access (based on other attached policies).

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowViewAccountInfo",
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:ListVirtualMFADevices"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowManageOwnPasswords",
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:GetUser"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnAccessKeys",
            "Effect": "Allow",
            "Action": [
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "iam:ListAccessKeys",
                "iam:UpdateAccessKey",
                "iam:GetAccessKeyLastUsed"
            ],
            "Resource": "arn:aws:iam::*:user/${aws:username}"
        },
        {
            "Sid": "AllowManageOwnMFA",
            "Effect": "Allow",
            "Action": [
                "iam:CreateVirtualMFADevice",
                "iam:DeleteVirtualMFADevice",
                "iam:ListMFADevices",
                "iam:EnableMFADevice",
                "iam:ResyncMFADevice"
            ],
            "Resource": [
                "arn:aws:iam::*:mfa/${aws:username}",
                "arn:aws:iam::*:user/${aws:username}"
            ]
        },
        {
            "Sid": "AllowDeactivateOwnMFAOnlyWhenUsingMFA",
            "Effect": "Allow",
            "Action": [
                "iam:DeactivateMFADevice"
            ],
            "Resource": [
                "arn:aws:iam::*:mfa/${aws:username}",
                "arn:aws:iam::*:user/${aws:username}"
            ],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        },
        {
            "Sid": "DenyAllExceptListedIfNoMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:GetUser",
                "iam:GetMFADevice",
                "iam:ListMFADevices",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "sts:GetSessionToken",
                "iam:ChangePassword",
                "iam:GetAccountPasswordPolicy"
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}
```

### How to Apply

1. **Create the policy:**
   - Go to IAM → Policies → Create policy
   - Select JSON tab and paste the policy above
   - Name it `EnforceMFAForHumanUsers`

2. **Attach to users/groups:**
   - Attach to a group called `HumanUsers` or similar
   - Add all human IAM users to this group
   - Do NOT attach to service accounts/bots

3. **User workflow after policy is applied:**
   - User logs into AWS Console
   - Can only set up MFA (most actions denied)
   - Sets up MFA device in Security credentials
   - Signs out and signs back in with MFA
   - Now has full access based on other policies

### Service Accounts vs Human Users

| Type | MFA Required? | Policy |
|------|---------------|--------|
| Human users | ✅ Yes | Apply `EnforceMFAForHumanUsers` policy |
| Service accounts | ❌ No | Do NOT apply MFA enforcement |
| CI/CD pipelines | ❌ No | Use IAM roles with assume-role |

> **Best practice**: Use IAM roles for service accounts and CI/CD, not long-term access keys. This tool is designed for human users only.

### Testing the Policy

After applying the policy, test with a user that has MFA:

```bash
# Without MFA - should fail
aws sts get-caller-identity --profile myprofile-long-term

# With MFA (using this tool) - should succeed
./aws_mfa_login.py --profile myprofile
aws sts get-caller-identity --profile myprofile
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - feel free to use and modify as needed.

## Acknowledgments

Inspired by [aws-mfa](https://github.com/broamski/aws-mfa) and the need for a simpler multi-profile MFA workflow.
