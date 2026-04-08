# Lab 1: Password Policy Verification

## Overview

This lab teaches GRC engineers how to validate AWS account password policies using Python to ensure compliance with identity management requirements. You'll learn to programmatically assess whether your organization's password policies meet SOC 2 and NIST standards, with intelligent detection of both traditional IAM and AWS Identity Center authentication scenarios.

## Why This Matters

Password policies are foundational to identity security. Auditors frequently request evidence that password complexity, length, and rotation requirements are properly configured. This lab automates the collection of that evidence and adapts to modern federated authentication architectures.

## Control Mapping

- **SOC 2 CC6.2** – Logical access security measures
- **NIST 800-53 IA-5** – Authenticator management

## Learning Objectives

By completing this lab, you will:

1. Query AWS IAM account password policies programmatically
2. Detect and handle AWS Identity Center (federated) authentication
3. Map technical evidence to compliance requirements
4. Generate audit-ready documentation for different authentication scenarios
5. Understand password policy best practices for compliance

## Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.9+ installed
- Basic familiarity with AWS IAM and Identity Center
- Understanding of virtual environments
- Windsurf IDE (download at: https://windsurf.com/refer?referral_code=l8ckp786a0dhgm96)

## Lab Setup Guide

### Step 1: Download and Setup Lab Files

1. **Download the lab files** from the provided ZIP archive
2. **Extract the ZIP file** to a new folder on your local machine (e.g., `GRC_Labs`)
3. **Open Windsurf IDE** and create a new workspace
4. **Open the lab folder** in Windsurf IDE:
   ```
   File → Open Folder → Navigate to extracted folder → 
   Select: lab-1-password-policy-verification
   ```
5. **Navigate to the lab directory** in your terminal:
   ```bash
   cd /path/to/your/extracted/folder/lab-1-password-policy-verification
   ```

### Step 2: Create and Activate Virtual Environment

**Why use a virtual environment?**
Virtual environments isolate Python dependencies, preventing conflicts between different projects and ensuring consistent, reproducible environments.

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate

# Verify activation (you should see (venv) in your prompt)
which python
```

### Step 3: Install Dependencies

```bash
# Install required packages
pip install boto3

# Verify installation
pip list
```

### Step 4: Configure AWS Authentication

Choose one of the following methods:

#### Option A: AWS SSO/Identity Center (Recommended)
```bash
# Configure SSO
aws configure sso

# Test connection
aws sts get-caller-identity --profile your-profile-name
```

#### Option B: Traditional AWS CLI
```bash
# Configure credentials
aws configure

# Test connection
aws sts get-caller-identity
```

## Required AWS Permissions

Your AWS credentials need the following IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "sso:ListInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

## Running the Lab

### Basic Usage

```bash
# Activate virtual environment (if not already active)
source venv/bin/activate

# Run with default credentials
python password_policy_checker.py

# Run with specific AWS profile
python password_policy_checker.py --profile your-profile-name

# Run with different region
python password_policy_checker.py --profile your-profile-name --region us-west-2
```

### Command Line Options

```bash
python password_policy_checker.py --help
```

**Available options:**
- `--profile`: AWS profile name for authentication
- `--region`: AWS region (default: us-east-1)
- `--output-dir`: Directory for output files (default: current directory)

## Understanding the Results

### Scenario 1: Identity Center Environment

If your account uses AWS Identity Center (common in enterprise environments):

```
🔐 Identity Center detected - federated authentication in use
💡 Password policies are managed in Identity Center, not IAM
ℹ️  No IAM console users found - IAM password policy not applicable
```

**Result:** `IDENTITY_CENTER_MANAGED` status with guidance to check Identity Center console.

### Scenario 2: Traditional IAM Environment

If your account uses traditional IAM users:

```
📋 Retrieving IAM account password policy...
✅ IAM password policy retrieved successfully
🔍 Evaluating password policy against compliance standards...
```

**Result:** Detailed compliance evaluation against SOC 2 and NIST standards.

### Scenario 3: Hybrid Environment

If your account has both Identity Center and IAM console users:

```
⚠️  Found X IAM console users - hybrid authentication detected
📋 Retrieving IAM account password policy...
```

**Result:** Full IAM policy evaluation with Identity Center context noted.

## Generated Reports

The script produces two files:

### 1. JSON Report (`password_policy_compliance_report.json`)
Detailed technical report including:
- Complete policy configuration
- Compliance evaluation results
- Remediation recommendations
- Authentication context

### 2. CSV Summary (`password_policy_compliance_summary.csv`)
Audit-ready summary with:
- Compliance score and status
- Control-by-control evaluation
- Priority-based recommendations

## Testing Different Scenarios

### Test with Identity Center Account (Current Setup)
```bash
python password_policy_checker.py --profile Toyeeb
```

### Create Test IAM User for Full Evaluation
```bash
# Create test user with console access
aws iam create-user --user-name test-console-user --profile Toyeeb

# Create login profile
aws iam create-login-profile \
  --user-name test-console-user \
  --password TempPassword123! \
  --password-reset-required \
  --profile Toyeeb

# Create basic password policy
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --no-hard-expiry \
  --profile Toyeeb
# Re-run assessment
python password_policy_checker.py --profile Toyeeb

# Clean up test resources
aws iam delete-login-profile --user-name test-console-user --profile Toyeeb
aws iam delete-user --user-name test-console-user --profile Toyeeb
aws iam delete-account-password-policy --profile Toyeeb
```

## Success Criteria

- [ ] Virtual environment created and activated successfully
- [ ] Dependencies installed without conflicts
- [ ] Script connects to AWS account successfully
- [ ] Authentication method (IAM vs Identity Center) detected correctly
- [ ] Appropriate compliance evaluation performed
- [ ] Evidence files generated in required formats
- [ ] Results interpreted correctly for audit purposes

## Troubleshooting

### Virtual Environment Issues
```bash
# If activation fails
which python
python -m venv --help

# If pip install fails
pip install --upgrade pip
pip install boto3 --verbose
```

### AWS Authentication Issues
```bash
# Check AWS configuration
aws configure list
aws sts get-caller-identity

# For SSO profiles
aws sso login --profile your-profile-name
```

### Permission Issues
```bash
# Test specific permissions
aws iam get-account-password-policy --profile your-profile-name
aws iam list-users --max-items 1 --profile your-profile-name
```

### Common Error Messages

**"No module named 'boto3'"**
- Ensure virtual environment is activated
- Run `pip install boto3`

**"Profile not found"**
- Check profile name: `aws configure list-profiles`
- Verify SSO login: `aws sso login --profile profile-name`

**"Access denied"**
- Verify IAM permissions listed above
- Check if you're using the correct AWS account

## Compliance Interpretation

### For Auditors

**Identity Center Environments:**
- Password policies managed centrally in Identity Center
- IAM password policy evaluation not applicable
- Recommend reviewing Identity Center password policy configuration

**Traditional IAM Environments:**
- Direct evaluation against SOC 2 CC6.2 and NIST IA-5
- Specific recommendations for non-compliant controls
- Ready-to-submit compliance evidence

**Hybrid Environments:**
- IAM policy applies to console users
- Identity Center policies apply to federated users
- Both systems require evaluation

## Next Steps

After completing this lab:

1. **Review Results**: Analyze generated reports with your compliance team
2. **Implement Recommendations**: Address any identified policy gaps
3. **Automate Monitoring**: Consider scheduling regular assessments
4. **Proceed to Lab 2**: Continue with Inactive Key Rotation Check
5. **Documentation**: Save reports for audit evidence

## Real-World Application

This lab simulates common audit requests:
- "Please provide evidence of your password policy configuration"
- "How do you ensure password complexity requirements are enforced?"
- "Demonstrate compliance with SOC 2 CC6.2 password controls"

The generated reports can be directly submitted to auditors as compliance evidence, with the script's intelligence ensuring appropriate evaluation based on your authentication architecture.

## Cleanup

When finished with the lab:

```bash
# Deactivate virtual environment
deactivate

# Optional: Remove virtual environment
rm -rf venv

# Keep generated reports for audit evidence
ls *.json *.csv
```
