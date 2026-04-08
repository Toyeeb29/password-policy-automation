#!/usr/bin/env python3
"""
AWS Password Policy Verification Tool
====================================

This script validates AWS account password policies against SOC 2 and NIST 800-53 compliance requirements.
It generates audit-ready evidence in JSON and CSV formats.

Control Mappings:
- SOC 2 CC6.2: Logical access security measures
- NIST 800-53 IA-5: Authenticator management
"""

import boto3
import json
import csv
import argparse
import sys
from datetime import datetime, timezone
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


class PasswordPolicyChecker:
    """
    A comprehensive AWS password policy compliance checker.

    This class handles the retrieval and evaluation of AWS account password policies
    against established security standards and generates compliance reports.
    """

    def __init__(self, profile_name=None, region='us-east-1'):
        self.profile_name = profile_name
        self.region = region
        self.session = None
        self.iam_client = None
        self.account_id = None

        # Compliance standards for password policies
        self.compliance_standards = {
            'minimum_password_length': 12,
            'require_symbols': True,
            'require_numbers': True,
            'require_uppercase': True,
            'require_lowercase': True,
            'max_password_age': 90,
            'password_reuse_prevention': 12,
            'allow_users_to_change_password': True,
            'hard_expiry': False
        }

        # ✅ FIX: Mapping from compliance keys to AWS API response keys
        self.key_mapping = {
            'minimum_password_length': 'MinimumPasswordLength',
            'require_symbols': 'RequireSymbols',
            'require_numbers': 'RequireNumbers',
            'require_uppercase': 'RequireUppercaseCharacters',
            'require_lowercase': 'RequireLowercaseCharacters',
            'max_password_age': 'MaxPasswordAge',
            'password_reuse_prevention': 'PasswordReusePrevention',
            'allow_users_to_change_password': 'AllowUsersToChangePassword',
            'hard_expiry': 'HardExpiry'
        }

    def initialize_aws_session(self):
        try:
            if self.profile_name:
                print(f"🔐 Initializing AWS session with profile: {self.profile_name}")
                self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region)
            else:
                print("🔐 Initializing AWS session with default credentials")
                self.session = boto3.Session(region_name=self.region)

            self.iam_client = self.session.client('iam')

            sts_client = self.session.client('sts')
            caller_identity = sts_client.get_caller_identity()
            self.account_id = caller_identity['Account']

            print(f"✅ Successfully connected to AWS Account: {self.account_id}")
            return True

        except ProfileNotFound:
            print(f"❌ Error: AWS profile '{self.profile_name}' not found")
            print("💡 Available profiles can be listed with: aws configure list-profiles")
            return False

        except NoCredentialsError:
            print("❌ Error: No AWS credentials found")
            print("💡 Please configure AWS credentials using: aws configure")
            return False

        except Exception as e:
            print(f"❌ Error initializing AWS session: {str(e)}")
            return False

    def check_identity_center_usage(self):
        try:
            sso_admin_client = self.session.client('sso-admin')
            instances = sso_admin_client.list_instances()

            if instances['Instances']:
                return {
                    'uses_identity_center': True,
                    'instance_arn': instances['Instances'][0]['InstanceArn'],
                    'identity_store_id': instances['Instances'][0]['IdentityStoreId']
                }
            else:
                return {'uses_identity_center': False}

        except ClientError as e:
            if e.response['Error']['Code'] in ['AccessDenied', 'UnauthorizedOperation']:
                return {'uses_identity_center': False, 'detection_limited': True}
            return {'uses_identity_center': False}
        except Exception:
            return {'uses_identity_center': False}

    def check_iam_user_count(self):
        try:
            paginator = self.iam_client.get_paginator('list_users')
            user_count = 0
            console_users = 0

            for page in paginator.paginate():
                for user in page['Users']:
                    user_count += 1
                    try:
                        self.iam_client.get_login_profile(UserName=user['UserName'])
                        console_users += 1
                    except ClientError:
                        pass

            return {
                'total_users': user_count,
                'console_users': console_users,
                'programmatic_only_users': user_count - console_users
            }
        except Exception as e:
            print(f"⚠️  Could not retrieve IAM user statistics: {str(e)}")
            return {'total_users': 0, 'console_users': 0, 'programmatic_only_users': 0}

    def get_password_policy(self):
        try:
            print("📋 Analyzing authentication configuration...")

            identity_center_info = self.check_identity_center_usage()
            iam_stats = self.check_iam_user_count()

            print(f"👥 IAM Users: {iam_stats['total_users']} total, {iam_stats['console_users']} with console access")

            if identity_center_info['uses_identity_center']:
                print("🔐 Identity Center detected - federated authentication in use")
                print("💡 Password policies are managed in Identity Center, not IAM")

                if iam_stats['console_users'] == 0:
                    print("ℹ️  No IAM console users found - IAM password policy not applicable")
                    return {
                        'policy_type': 'identity_center',
                        'iam_policy_applicable': False,
                        'identity_center_arn': identity_center_info.get('instance_arn'),
                        'iam_users': iam_stats
                    }
                else:
                    print(f"⚠️  Found {iam_stats['console_users']} IAM console users - hybrid authentication detected")

            print("📋 Retrieving IAM account password policy...")
            response = self.iam_client.get_account_password_policy()
            policy = response['PasswordPolicy']

            policy['policy_type'] = 'iam'
            policy['iam_policy_applicable'] = True
            policy['identity_center_info'] = identity_center_info
            policy['iam_users'] = iam_stats

            print("✅ IAM password policy retrieved successfully")
            return policy

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'NoSuchEntity':
                identity_center_info = self.check_identity_center_usage()
                iam_stats = self.check_iam_user_count()

                if identity_center_info['uses_identity_center'] and iam_stats['console_users'] == 0:
                    print("ℹ️  No IAM password policy needed - using Identity Center for authentication")
                    return {
                        'policy_type': 'identity_center',
                        'iam_policy_applicable': False,
                        'identity_center_arn': identity_center_info.get('instance_arn'),
                        'iam_users': iam_stats,
                        'recommendation': 'Verify password policies in Identity Center console'
                    }
                else:
                    print("⚠️  No IAM password policy configured for this AWS account")
                    return None

            elif error_code == 'AccessDenied':
                print("❌ Access denied: Insufficient permissions to read password policy")
                print("💡 Required permission: iam:GetAccountPasswordPolicy")
                return None
            else:
                print(f"❌ Error retrieving password policy: {e.response['Error']['Message']}")
                return None

        except Exception as e:
            print(f"❌ Unexpected error retrieving password policy: {str(e)}")
            return None

    def evaluate_policy_compliance(self, policy):
        print("🔍 Evaluating password policy against compliance standards...")

        evaluation = {
            'compliant_controls': [],
            'non_compliant_controls': [],
            'missing_controls': [],
            'compliance_score': 0,
            'soc2_cc6_2_status': 'UNKNOWN',
            'nist_ia_5_status': 'UNKNOWN',
            'overall_status': 'UNKNOWN',
            'policy_type': 'unknown'
        }

        if policy is None:
            evaluation['missing_controls'] = list(self.compliance_standards.keys())
            evaluation['soc2_cc6_2_status'] = 'NON_COMPLIANT'
            evaluation['nist_ia_5_status'] = 'NON_COMPLIANT'
            evaluation['overall_status'] = 'NON_COMPLIANT'
            evaluation['policy_type'] = 'none'
            return evaluation

        if policy.get('policy_type') == 'identity_center':
            evaluation['policy_type'] = 'identity_center'
            evaluation['soc2_cc6_2_status'] = 'MANAGED_EXTERNALLY'
            evaluation['nist_ia_5_status'] = 'MANAGED_EXTERNALLY'
            evaluation['overall_status'] = 'IDENTITY_CENTER_MANAGED'
            evaluation['compliance_score'] = 100
            print("ℹ️  Password policies managed by Identity Center - IAM evaluation not applicable")
            return evaluation

        total_controls = len(self.compliance_standards)
        compliant_count = 0

        # ✅ FIX: Use key_mapping to get correct AWS API key names
        for control, required_value in self.compliance_standards.items():
            aws_key = self.key_mapping.get(control, control)
            current_value = policy.get(aws_key)

            if current_value is None:
                evaluation['missing_controls'].append(control)
                print(f"  ⚠️  Missing: {control}")
            elif self._is_control_compliant(control, current_value, required_value):
                evaluation['compliant_controls'].append({
                    'control': control,
                    'current_value': current_value,
                    'required_value': required_value,
                    'status': 'COMPLIANT'
                })
                compliant_count += 1
                print(f"  ✅ Compliant: {control} (current: {current_value}, required: {required_value})")
            else:
                evaluation['non_compliant_controls'].append({
                    'control': control,
                    'current_value': current_value,
                    'required_value': required_value,
                    'status': 'NON_COMPLIANT'
                })
                print(f"  ❌ Non-compliant: {control} (current: {current_value}, required: {required_value})")

        evaluation['compliance_score'] = round((compliant_count / total_controls) * 100, 2)

        if evaluation['compliance_score'] >= 90:
            evaluation['overall_status'] = 'COMPLIANT'
            evaluation['soc2_cc6_2_status'] = 'COMPLIANT'
            evaluation['nist_ia_5_status'] = 'COMPLIANT'
        elif evaluation['compliance_score'] >= 70:
            evaluation['overall_status'] = 'PARTIALLY_COMPLIANT'
            evaluation['soc2_cc6_2_status'] = 'PARTIALLY_COMPLIANT'
            evaluation['nist_ia_5_status'] = 'PARTIALLY_COMPLIANT'
        else:
            evaluation['overall_status'] = 'NON_COMPLIANT'
            evaluation['soc2_cc6_2_status'] = 'NON_COMPLIANT'
            evaluation['nist_ia_5_status'] = 'NON_COMPLIANT'

        print(f"📊 Compliance Score: {evaluation['compliance_score']}% ({compliant_count}/{total_controls} controls)")

        return evaluation

    def _is_control_compliant(self, control, current_value, required_value):
        if isinstance(required_value, bool):
            return current_value == required_value
        elif isinstance(required_value, int):
            if control in ['minimum_password_length', 'password_reuse_prevention']:
                return current_value >= required_value
            elif control == 'max_password_age':
                return current_value <= required_value
            else:
                return current_value == required_value
        else:
            return current_value == required_value

    def generate_recommendations(self, evaluation, policy):
        recommendations = []

        if policy is None:
            recommendations.append({
                'priority': 'HIGH',
                'control': 'password_policy',
                'issue': 'No password policy configured',
                'recommendation': 'Create an AWS account password policy with minimum security requirements',
                'aws_cli_command': 'aws iam update-account-password-policy --minimum-password-length 12 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 12 --allow-users-to-change-password'
            })
            return recommendations

        for control_info in evaluation['non_compliant_controls']:
            control = control_info['control']
            current = control_info['current_value']
            required = control_info['required_value']

            if control == 'minimum_password_length':
                recommendations.append({
                    'priority': 'HIGH',
                    'control': control,
                    'issue': f'Password length too short (current: {current}, required: {required})',
                    'recommendation': f'Increase minimum password length to {required} characters',
                    'aws_cli_command': f'aws iam update-account-password-policy --minimum-password-length {required}'
                })
            elif control == 'max_password_age':
                recommendations.append({
                    'priority': 'MEDIUM',
                    'control': control,
                    'issue': f'Password age too long (current: {current}, required: ≤{required})',
                    'recommendation': f'Reduce maximum password age to {required} days',
                    'aws_cli_command': f'aws iam update-account-password-policy --max-password-age {required}'
                })
            elif control.startswith('require_'):
                feature = control.replace('require_', '').replace('_', ' ')
                recommendations.append({
                    'priority': 'HIGH',
                    'control': control,
                    'issue': f'{feature.title()} not required in passwords',
                    'recommendation': f'Enable requirement for {feature} in passwords',
                    'aws_cli_command': f'aws iam update-account-password-policy --{control.replace("_", "-")}'
                })

        for control in evaluation['missing_controls']:
            required = self.compliance_standards[control]
            recommendations.append({
                'priority': 'HIGH',
                'control': control,
                'issue': 'Control not configured',
                'recommendation': f'Configure {control} with value: {required}',
                'aws_cli_command': f'aws iam update-account-password-policy --{control.replace("_", "-")} {required}'
            })

        return recommendations

    def generate_json_report(self, policy, evaluation, recommendations):
        report = {
            'metadata': {
                'report_type': 'AWS Password Policy Compliance Assessment',
                'account_id': self.account_id,
                'assessment_date': datetime.now(timezone.utc).isoformat(),
                'aws_region': self.region,
                'aws_profile': self.profile_name,
                'tool_version': '1.1',
                'standards_evaluated': ['SOC 2 CC6.2', 'NIST 800-53 IA-5']
            },
            'password_policy': policy if policy else {},
            'compliance_standards': self.compliance_standards,
            'evaluation': evaluation,
            'recommendations': recommendations,
            'summary': {
                'policy_configured': policy is not None,
                'compliance_score': evaluation['compliance_score'],
                'total_controls': len(self.compliance_standards),
                'compliant_controls': len(evaluation['compliant_controls']),
                'non_compliant_controls': len(evaluation['non_compliant_controls']),
                'missing_controls': len(evaluation['missing_controls']),
                'high_priority_recommendations': len([r for r in recommendations if r['priority'] == 'HIGH'])
            }
        }

        return report

    def save_json_report(self, report, filename='password_policy_compliance_report.json'):
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"📄 JSON report saved: {filename}")
        except Exception as e:
            print(f"❌ Error saving JSON report: {str(e)}")

    def save_csv_report(self, evaluation, recommendations, filename='password_policy_compliance_summary.csv'):
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)

                writer.writerow(['AWS Password Policy Compliance Summary'])
                writer.writerow(['Account ID', self.account_id])
                writer.writerow(['Assessment Date', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')])
                writer.writerow(['Compliance Score', f"{evaluation['compliance_score']}%"])
                writer.writerow(['Overall Status', evaluation['overall_status']])
                writer.writerow([])

                writer.writerow(['Control Name', 'Status', 'Current Value', 'Required Value', 'Priority'])

                for control in evaluation['compliant_controls']:
                    writer.writerow([
                        control['control'],
                        'COMPLIANT',
                        control['current_value'],
                        control['required_value'],
                        'N/A'
                    ])

                for control in evaluation['non_compliant_controls']:
                    writer.writerow([
                        control['control'],
                        'NON_COMPLIANT',
                        control['current_value'],
                        control['required_value'],
                        'HIGH'
                    ])

                for control in evaluation['missing_controls']:
                    required_value = self.compliance_standards[control]
                    writer.writerow([
                        control,
                        'MISSING',
                        'Not Configured',
                        required_value,
                        'HIGH'
                    ])

                writer.writerow([])
                writer.writerow(['Remediation Recommendations'])
                writer.writerow(['Priority', 'Control', 'Issue', 'Recommendation'])

                for rec in recommendations:
                    writer.writerow([
                        rec['priority'],
                        rec['control'],
                        rec['issue'],
                        rec['recommendation']
                    ])

            print(f"📊 CSV report saved: {filename}")

        except Exception as e:
            print(f"❌ Error saving CSV report: {str(e)}")

    def run_assessment(self):
        print("🚀 Starting AWS Password Policy Compliance Assessment")
        print("=" * 60)

        if not self.initialize_aws_session():
            return False

        policy = self.get_password_policy()
        evaluation = self.evaluate_policy_compliance(policy)
        recommendations = self.generate_recommendations(evaluation, policy)

        print("\n📋 Generating compliance reports...")
        json_report = self.generate_json_report(policy, evaluation, recommendations)

        self.save_json_report(json_report)
        self.save_csv_report(evaluation, recommendations)

        print("\n" + "=" * 60)
        print("📊 ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"Account ID: {self.account_id}")
        print(f"Compliance Score: {evaluation['compliance_score']}%")
        print(f"Overall Status: {evaluation['overall_status']}")
        print(f"SOC 2 CC6.2: {evaluation['soc2_cc6_2_status']}")
        print(f"NIST IA-5: {evaluation['nist_ia_5_status']}")
        print(f"High Priority Recommendations: {len([r for r in recommendations if r['priority'] == 'HIGH'])}")

        if evaluation['overall_status'] == 'COMPLIANT':
            print("✅ Password policy meets compliance requirements!")
        else:
            print("⚠️  Password policy requires attention - see recommendations above")

        return True


def main():
    parser = argparse.ArgumentParser(
        description='AWS Password Policy Compliance Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_policy_checker.py
  python password_policy_checker.py --profile production
  python password_policy_checker.py --profile dev --region us-west-2

This tool evaluates AWS account password policies against SOC 2 and NIST 800-53 standards.
        """
    )

    parser.add_argument('--profile', type=str, help='AWS profile name to use for authentication (optional)')
    parser.add_argument('--region', type=str, default='us-east-1', help='AWS region to use (default: us-east-1)')
    parser.add_argument('--output-dir', type=str, default='.', help='Directory to save output files (default: current directory)')

    args = parser.parse_args()

    checker = PasswordPolicyChecker(
        profile_name=args.profile,
        region=args.region
    )

    success = checker.run_assessment()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()