"""
AI Shield SaaS — AWS Cloud Integration Service.
Implements secure, least-privilege AWS integration using AWS STS AssumeRole with external IDs.
Collects CloudTrail management events, Security Hub findings, and resource posture
without requiring permanent keys or root credentials.
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError, ParamValidationError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    ClientError = Exception
    NoCredentialsError = Exception
    EndpointConnectionError = Exception
    ParamValidationError = Exception

logger = logging.getLogger("aishield.aws")

class AWSIntegrationService:
    """
    Manages customer AWS cloud connections through STS AssumeRole.
    Enforces read-only access and organization tenant isolation.
    """

    DEFAULT_SESSION_NAME = "AIShieldSecurityAuditSession"
    DEFAULT_DURATION_SECONDS = 3600

    @staticmethod
    def validate_account_id(account_id: str) -> bool:
        """Validate that AWS Account ID is a valid 12-digit string."""
        return bool(re.match(r"^\d{12}$", account_id.strip()))

    @staticmethod
    def validate_role_arn(role_arn: str) -> bool:
        """Validate that IAM Role ARN conforms to standard AWS format."""
        return bool(re.match(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]+$", role_arn.strip()))

    @classmethod
    def generate_trust_policy(cls, external_id: str, caller_arn: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate least-privilege IAM Trust Policy for customer's AWS role.
        Restricts AssumeRole strictly to AI Shield's identity with the organization's unique External ID.
        """
        principal_arn = caller_arn or os.environ.get("AWS_AISHIELD_SERVICE_ARN", "arn:aws:iam::000000000000:root")
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": principal_arn
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": external_id
                        }
                    }
                }
            ]
        }

    @classmethod
    def get_temporary_session(cls, role_arn: str, external_id: str, region_name: str = "us-east-1") -> Tuple[Optional[Any], Optional[str]]:
        """
        Assume IAM role using AWS STS AssumeRole and return a scoped boto3 Session.
        Returns: (boto3.Session or None, error_message or None)
        """
        if not BOTO3_AVAILABLE:
            return None, "boto3 library is not available in backend environment"

        if not cls.validate_role_arn(role_arn):
            return None, f"Invalid IAM Role ARN format: '{role_arn}'. Expected format: arn:aws:iam::<12-digit-account-id>:role/<role-name>"

        if not external_id or len(external_id.strip()) < 8:
            return None, "External ID is required and must be at least 8 characters for STS boundary protection"

        try:
            # Create base STS client with backend credentials or default profile
            sts_client = boto3.client("sts", region_name=region_name)
            response = sts_client.assume_role(
                RoleArn=role_arn.strip(),
                RoleSessionName=cls.DEFAULT_SESSION_NAME,
                ExternalId=external_id.strip(),
                DurationSeconds=cls.DEFAULT_DURATION_SECONDS
            )

            credentials = response["Credentials"]
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=region_name
            )
            return session, None

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.warning(f"[AWS] STS AssumeRole rejected ({code}): {msg}")
            return None, f"AWS STS AssumeRole Error ({code}): {msg}"
        except NoCredentialsError:
            return None, "Backend AWS credentials are not configured to perform sts:AssumeRole. Please set AWS_ACCESS_KEY_ID or IAM task role."
        except EndpointConnectionError as e:
            return None, f"Cannot connect to AWS STS endpoint: {e}"
        except Exception as e:
            return None, f"Unexpected STS AssumeRole failure: {str(e)}"

    @classmethod
    def test_connection(cls, account_id: str, role_arn: str, external_id: str, regions: List[str]) -> Dict[str, Any]:
        """
        Validate AWS credentials and test read-only permissions.
        NEVER reports success unless live STS authentication actually succeeds.
        """
        if not account_id or not cls.validate_account_id(account_id):
            return {
                "is_connected": False,
                "status": "UNCONFIGURED",
                "error": "Valid 12-digit AWS Account ID is required",
                "trust_policy": cls.generate_trust_policy(external_id)
            }

        if not role_arn or not cls.validate_role_arn(role_arn):
            return {
                "is_connected": False,
                "status": "UNCONFIGURED",
                "error": "Valid IAM Role ARN is required (e.g. arn:aws:iam::123456789012:role/AIShieldRole)",
                "trust_policy": cls.generate_trust_policy(external_id)
            }

        primary_region = regions[0] if regions else "us-east-1"
        session, err = cls.get_temporary_session(role_arn, external_id, region_name=primary_region)

        if err or session is None:
            return {
                "is_connected": False,
                "status": "AUTHENTICATION_FAILED",
                "error": err,
                "trust_policy": cls.generate_trust_policy(external_id),
                "tested_at": datetime.now(timezone.utc).isoformat()
            }

        # Verify identity using assumed credentials
        try:
            sts_assumed = session.client("sts")
            caller = sts_assumed.get_caller_identity()
            assumed_arn = caller.get("Arn", "")

            # Test read-only IAM access if allowed
            iam_summary = {}
            try:
                iam = session.client("iam")
                summary = iam.get_account_summary()
                iam_summary = summary.get("SummaryMap", {})
            except Exception:
                # Least-privilege roles might only have CloudTrail / Security Hub
                iam_summary = {"info": "IAM summary read restricted by least-privilege policy"}

            return {
                "is_connected": True,
                "status": "CONNECTED",
                "account_id": account_id,
                "assumed_role_arn": assumed_arn,
                "regions": regions,
                "iam_summary": iam_summary,
                "error": None,
                "tested_at": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            return {
                "is_connected": False,
                "status": "ERROR",
                "error": f"Failed caller verification under assumed role: {str(e)}",
                "trust_policy": cls.generate_trust_policy(external_id),
                "tested_at": datetime.now(timezone.utc).isoformat()
            }

    @classmethod
    def fetch_cloudtrail_events(cls, role_arn: str, external_id: str, regions: List[str], limit: int = 20) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Pull recent CloudTrail management events via assumed role.
        """
        primary_region = regions[0] if regions else "us-east-1"
        session, err = cls.get_temporary_session(role_arn, external_id, region_name=primary_region)
        if err or session is None:
            return [], err

        try:
            ct = session.client("cloudtrail", region_name=primary_region)
            response = ct.lookup_events(MaxResults=min(limit, 50))
            events = []
            for ev in response.get("Events", []):
                events.append({
                    "event_id": ev.get("EventId"),
                    "event_name": ev.get("EventName"),
                    "event_time": ev.get("EventTime").isoformat() if ev.get("EventTime") else None,
                    "event_source": ev.get("EventSource"),
                    "username": ev.get("Username", "Unknown"),
                    "read_only": ev.get("ReadOnly", False),
                    "resources": [r.get("ResourceName") for r in ev.get("Resources", []) if r.get("ResourceName")]
                })
            return events, None
        except Exception as e:
            return [], f"CloudTrail event lookup failed: {str(e)}"

    @classmethod
    def fetch_security_hub_findings(cls, role_arn: str, external_id: str, regions: List[str], limit: int = 20) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Pull AWS Security Hub findings via assumed role.
        """
        primary_region = regions[0] if regions else "us-east-1"
        session, err = cls.get_temporary_session(role_arn, external_id, region_name=primary_region)
        if err or session is None:
            return [], err

        try:
            sh = session.client("securityhub", region_name=primary_region)
            response = sh.get_findings(MaxResults=min(limit, 50))
            findings = []
            for f in response.get("Findings", []):
                findings.append({
                    "id": f.get("Id"),
                    "title": f.get("Title"),
                    "severity": f.get("Severity", {}).get("Label", "MEDIUM"),
                    "description": f.get("Description"),
                    "resource_type": f.get("Resources", [{}])[0].get("Type") if f.get("Resources") else "Unknown",
                    "updated_at": f.get("UpdatedAt")
                })
            return findings, None
        except Exception as e:
            return [], f"Security Hub findings lookup failed: {str(e)}"
