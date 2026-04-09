# 🔐 AWS Password Policy Compliance Checker

A Python-based GRC automation tool that validates AWS account password policies against **SOC 2 CC6.2** and **NIST 800-53 IA-5** compliance standards. Built as part of my hands-on GRC engineering lab series.

---

## 📌 What This Does

This tool connects to your AWS account, retrieves your IAM password policy, and evaluates it against industry compliance standards. It automatically detects whether your account uses traditional IAM, AWS Identity Center (SSO), or a hybrid setup — and generates audit-ready reports accordingly.

---

## 🎯 Control Mapping

| Framework | Control | Description |
|-----------|---------|-------------|
| SOC 2 | CC6.2 | Logical access security measures |
| NIST 800-53 | IA-5 | Authenticator management |

---

## 🛠️ Tech Stack

- **Python 3.9+**
- **boto3** – AWS SDK for Python
- **AWS IAM** – Password policy evaluation
- **AWS IAM Identity Center** – SSO detection
- **AWS STS** – Account identity verification

---

## ⚙️ Setup

### 1. Clone the repository
```bash
git clone https://github.com/Toyeeb29/password-policy-automation.git
```

### 2. Create and activate a virtual environment
```bash
python -m venv venv

# Git Bash / macOS / Linux
source venv/Scripts/activate   # Windows Git Bash
source venv/bin/activate       # macOS/Linux
```

### 3. Install dependencies
```bash
pip install boto3
```

### 4. Configure AWS credentials

**Option A — AWS SSO (Identity Center):**
```bash
aws configure sso --profile YourProfileName
aws sso login --profile YourProfileName
```

**Option B — Traditional IAM:**
```bash
aws configure
```

---

## 🔑 Required AWS Permissions

Attach this policy to your IAM user or SSO permission set:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:UpdateAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:GetLoginProfile",
                "iam:CreateUser",
                "iam:CreateLoginProfile",
                "sso:ListInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## 🚀 Usage

```bash
# Run with your AWS SSO profile
python password_policy_checker.py --profile YourProfileName

# Run with a specific region
python password_policy_checker.py --profile YourProfileName --region us-east-1

# Run with default credentials
python password_policy_checker.py
```

---

## 📋 Setting a Compliant Password Policy

Before running the checker, make sure your AWS account has a password policy configured:

```bash
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
  --profile YourProfileName
```

---

## 📊 Sample Output

### Policy Evaluation — 9/9 Controls Compliant
<img width="578" height="383" alt="Verification 1" src="https://github.com/user-attachments/assets/8333f82e-cceb-4bf4-85ce-7398aef14591" />


### Assessment Summary — 100% Compliant
<img width="541" height="227" alt="Verification 2" src="https://github.com/user-attachments/assets/9e274121-59d0-438e-8c85-4884e28dc8f4" />

---

## 📁 Generated Reports

Each run produces two output files:

| File | Format | Purpose |
|------|--------|---------|
| `password_policy_compliance_report.json` | JSON | Detailed technical report for engineers |
| `password_policy_compliance_summary.csv` | CSV | Audit-ready summary for compliance teams |

---

## 🔍 How It Works

```
run_assessment()
      │
      ├── initialize_aws_session()      → Connect to AWS using profile
      ├── get_password_policy()         → Fetch IAM password policy
      │       ├── check_identity_center_usage()   → Detect SSO
      │       └── check_iam_user_count()          → Count console users
      ├── evaluate_policy_compliance()  → Compare against standards
      │       └── _is_control_compliant()         → Per-control logic
      ├── generate_recommendations()    
      └── save_json_report()
          save_csv_report()             → Output audit evidence
```

The key design decision is the **key mapping** — AWS returns policy fields in camelCase (`RequireUppercaseCharacters`) while the compliance standards use snake_case (`require_uppercase`). The script translates between both automatically.

---


## 🌐 Authentication Scenarios Supported

| Scenario | Detection | Evaluation |
|----------|-----------|------------|
| Traditional IAM only | ✅ Auto-detected | Full IAM policy evaluation |
| Identity Center (SSO) only | ✅ Auto-detected | Marked as externally managed |
| Hybrid (both) | ✅ Auto-detected | IAM policy evaluated + SSO noted |

---

## 🧹 Cleanup

```bash
# Deactivate virtual environment
deactivate

# Keep reports for audit evidence
ls *.json *.csv
```

---

## 📚 Lessons Learned

- AWS IAM Identity Center and traditional IAM require different compliance approaches
- The AWS API returns camelCase keys — always map them to your internal standard before comparing
- SSO permission sets must be **re-provisioned/updated** after policy changes for CLI sessions to reflect updates
- 
---


## 📄 License

MIT License — free to use, modify, and distribute.
