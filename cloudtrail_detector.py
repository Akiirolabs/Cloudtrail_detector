#!/usr/bin/env python3
"""
cloudtrail_detector.py

Advanced AWS CloudTrail detection script.

Usage:
    python cloudtrail_detector.py /path/to/cloudtrail/logs > alerts.json
"""

import json
import os
import sys
import glob
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List
from datetime import datetime, timedelta


# ------------- Helpers -------------


def parse_event_time(ts: str) -> datetime:
    """
    Parse CloudTrail eventTime string into a timezone naive UTC datetime.
    CloudTrail: "2025-11-30T15:04:05Z"
    """
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def safe_get(d: Dict[str, Any], path: List[str], default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


# ------------- Detection rule model -------------


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: str
    mitre: List[str]
    match: Callable[[Dict[str, Any], Dict[str, Any]], bool]


# ------------- Rule implementations -------------


def rule_root_console_login(evt: Dict[str, Any], state: Dict[str, Any]) -> bool:
    return (
        evt.get("eventName") == "ConsoleLogin"
        and safe_get(evt, ["userIdentity", "type"]) == "Root"
        and safe_get(evt, ["responseElements", "ConsoleLogin"]) == "Success"
    )


def rule_cloudtrail_modified(evt: Dict[str, Any], state: Dict[str, Any]) -> bool:
    if evt.get("eventSource") != "cloudtrail.amazonaws.com":
        return False

    sensitive_events = {
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
    }
    return evt.get("eventName") in sensitive_events


def rule_s3_bucket_made_public(evt: Dict[str, Any], state: Dict[str, Any]) -> bool:
    if evt.get("eventSource") != "s3.amazonaws.com":
        return False

    public_policy_indicators = [
        '"Principal":"*"',
        '"Principal": "*"',
        '"AllUsers"',
        '"AuthenticatedUsers"',
    ]

    event_name = evt.get("eventName")
    if event_name not in {"PutBucketPolicy", "PutBucketAcl"}:
        return False

    # Check requestParameters or resources for public indicators
    raw = json.dumps(evt.get("requestParameters", {}))
    return any(indicator in raw for indicator in public_policy_indicators)


def rule_kms_key_disabled_or_deleted(evt: Dict[str, Any], state: Dict[str, Any]) -> bool:
    if evt.get("eventSource") != "kms.amazonaws.com":
        return False

    sensitive_events = {
        "DisableKey",
        "ScheduleKeyDeletion",
    }
    return evt.get("eventName") in sensitive_events


def rule_many_unauthorized_calls(evt: Dict[str, Any], state: Dict[str, Any]) -> bool:
    """
    Simple version that fires on any AccessDenied related error.
    You can upgrade this to a threshold based rule per principal.
    """
    error_code = evt.get("errorCode", "")
    return "AccessDenied" in error_code or "UnauthorizedOperation" in error_code


def rule_new_user_became_admin(evt: Dict[str, Any], state: Dict[str, Any]) -> bool:
    """
    Correlated rule:
    - Track IAM CreateUser events and their times
    - Fire when a user gets Administrator access within a short time after creation
    """
    if evt.get("eventSource") != "iam.amazonaws.com":
        return False

    iam_state = state.setdefault("iam_users", {})

    event_name = evt.get("eventName")

    # Track creations
    if event_name == "CreateUser":
        user_name = safe_get(evt, ["responseElements", "user", "userName"]) or safe_get(
            evt, ["requestParameters", "userName"]
        )
        if user_name:
            iam_state[user_name] = parse_event_time(evt["eventTime"])
        return False

    # Look for admin privilege assignment
    admin_policy_arns = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
    }

    if event_name == "AttachUserPolicy":
        policy_arn = safe_get(evt, ["requestParameters", "policyArn"])
        user_name = safe_get(evt, ["requestParameters", "userName"])
        if not user_name or not policy_arn:
            return False

        if policy_arn in admin_policy_arns and user_name in iam_state:
            created_at = iam_state[user_name]
            now = parse_event_time(evt["eventTime"])
            # Within 30 minutes of creation
            return now - created_at <= timedelta(minutes=30)

    if event_name == "AddUserToGroup":
        group_name = safe_get(evt, ["requestParameters", "groupName"])
        user_name = safe_get(evt, ["requestParameters", "userName"])
        if not group_name or not user_name:
            return False

        admin_group_names = {"Admins", "Administrators", "Admin"}
        if group_name in admin_group_names and user_name in iam_state:
            created_at = iam_state[user_name]
            now = parse_event_time(evt["eventTime"])
            return now - created_at <= timedelta(minutes=30)

    return False


# ------------- Rule catalog -------------


RULES: List[DetectionRule] = [
    DetectionRule(
        rule_id="AWS-001",
        name="Root account console login",
        description="Root account performed a successful console login",
        severity="high",
        mitre=["T1078"],
        match=rule_root_console_login,
    ),
    DetectionRule(
        rule_id="AWS-002",
        name="CloudTrail configuration modified",
        description="CloudTrail logging was stopped, deleted, or modified",
        severity="critical",
        mitre=["T1562"],
        match=rule_cloudtrail_modified,
    ),
    DetectionRule(
        rule_id="AWS-003",
        name="S3 bucket made public",
        description="S3 bucket policy or ACL indicates public access",
        severity="high",
        mitre=["T1530", "T1537"],
        match=rule_s3_bucket_made_public,
    ),
    DetectionRule(
        rule_id="AWS-004",
        name="KMS key disabled or scheduled for deletion",
        description="KMS key was disabled or scheduled for deletion",
        severity="high",
        mitre=["T1485", "T1486"],
        match=rule_kms_key_disabled_or_deleted,
    ),
    DetectionRule(
        rule_id="AWS-005",
        name="Unauthorized or access denied API calls",
        description="API call failed with AccessDenied or UnauthorizedOperation",
        severity="medium",
        mitre=["T1078", "T1110"],
        match=rule_many_unauthorized_calls,
    ),
    DetectionRule(
        rule_id="AWS-006",
        name="New IAM user quickly granted admin privileges",
        description="New IAM user received admin rights shortly after creation",
        severity="critical",
        mitre=["T1078", "T1098"],
        match=rule_new_user_became_admin,
    ),
]


# ------------- Event loading -------------


def load_cloudtrail_events(path: str) -> List[Dict[str, Any]]:
    """
    Load CloudTrail events from a file or directory.
    Each file is expected to contain either:
      - A top level "Records" array (standard CloudTrail)
      - Or a list of events (streamed JSON)
    """
    files: List[str] = []

    if os.path.isdir(path):
        files = glob.glob(os.path.join(path, "*.json"))
    else:
        files = [path]

    events: List[Dict[str, Any]] = []

    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"Failed to read {f}: {e}", file=sys.stderr)
            continue

        if isinstance(data, dict) and "Records" in data:
            records = data["Records"]
        elif isinstance(data, list):
            records = data
        else:
            print(f"Unexpected JSON format in {f}", file=sys.stderr)
            continue

        for evt in records:
            if "eventTime" in evt:
                events.append(evt)

    # Sort by time for correlated rules
    events.sort(key=lambda e: e["eventTime"])
    return events


# ------------- Detection engine -------------


def generate_alert(rule: DetectionRule, evt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "description": rule.description,
        "mitre": rule.mitre,
        "eventTime": evt.get("eventTime"),
        "eventSource": evt.get("eventSource"),
        "eventName": evt.get("eventName"),
        "userIdentity": {
            "type": safe_get(evt, ["userIdentity", "type"]),
            "arn": safe_get(evt, ["userIdentity", "arn"]),
            "userName": safe_get(evt, ["userIdentity", "userName"]),
            "accountId": safe_get(evt, ["userIdentity", "accountId"]),
        },
        "sourceIPAddress": evt.get("sourceIPAddress"),
        "awsRegion": evt.get("awsRegion"),
        "requestParameters": evt.get("requestParameters"),
        "responseElements": evt.get("responseElements"),
        "errorCode": evt.get("errorCode"),
        "raw_event": evt,
    }


def run_detection(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    state: Dict[str, Any] = {}

    for evt in events:
        for rule in RULES:
            try:
                if rule.match(evt, state):
                    alerts.append(generate_alert(rule, evt))
            except Exception as e:
                # Avoid rule errors killing the pipeline
                print(
                    f"Rule {rule.rule_id} failed on event {evt.get('eventID', 'unknown')}: {e}",
                    file=sys.stderr,
                )
                continue

    return alerts


# ------------- Main entrypoint -------------


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python cloudtrail_detector.py /path/to/cloudtrail/logs_or_file.json",
            file=sys.stderr,
        )
        sys.exit(1)

    path = sys.argv[1]
    events = load_cloudtrail_events(path)
    alerts = run_detection(events)
    json.dump(alerts, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python cloudtrail_detector.py /path/to/cloudtrail/logs_or_file.json",
            file=sys.stderr,
        )
        sys.exit(1)

    path = sys.argv[1]
    events = load_cloudtrail_events(path)
    alerts = run_detection(events)
    json.dump(alerts, sys.stdout, indent=2)
