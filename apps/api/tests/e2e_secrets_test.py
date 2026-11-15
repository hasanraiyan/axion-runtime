#!/usr/bin/env python3
"""
Standalone End-to-End (E2E) Test for Axion Project Secrets Management (MOD-02).

This script performs pure HTTP API calls against http://localhost:8000.
NO APPLICATION CODE OR INTERNAL MODULES ARE IMPORTED.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

# Terminal colors for clean reporting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_step(title: str):
    print(f"\n{BOLD}{CYAN}=== {title} ==={RESET}")


def print_success(msg: str):
    print(f"  {GREEN}[PASS]{RESET} {msg}")


def print_fail(msg: str):
    print(f"  {RED}[FAIL]{RESET} {msg}")


def print_info(msg: str):
    print(f"  {YELLOW}[INFO]{RESET} {msg}")


class ApiTestClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        expected_status: Optional[int] = None,
    ) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        data_bytes = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data_bytes = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)

        status_code = 0
        response_data: Dict[str, Any] = {}
        resp_headers: Dict[str, str] = {}

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status_code = resp.status
                resp_headers = dict(resp.headers)
                raw_body = resp.read().decode("utf-8")
                if raw_body:
                    try:
                        response_data = json.loads(raw_body)
                    except Exception:
                        response_data = {"raw": raw_body}
        except urllib.error.HTTPError as e:
            status_code = e.code
            resp_headers = dict(e.headers)
            raw_body = e.read().decode("utf-8")
            if raw_body:
                try:
                    response_data = json.loads(raw_body)
                except Exception:
                    response_data = {"raw": raw_body}
        except Exception as ex:
            print_fail(f"Network / connection error: {ex}")
            raise ex

        print(f"  --> {method} {path} => HTTP {status_code}")

        if expected_status and status_code != expected_status:
            print_fail(
                f"Expected status {expected_status}, but received {status_code}. Response: {response_data}"
            )
        return status_code, response_data, resp_headers


def run_e2e_test(base_url: str, token: str, project_id: Optional[str] = None):
    client = ApiTestClient(base_url, token)

    # 1. Health check
    print_step("1. Checking Server Health")
    status, data, _ = client.request("GET", "/api/v1/health", expected_status=200)
    assert status == 200, f"Server health check failed: {data}"
    print_success(f"Server is healthy at {base_url} (Version: {data.get('data', {}).get('version')})")

    # 2. Auth me check
    print_step("2. Authenticating Current User (/api/v1/auth/me)")
    status, data, _ = client.request("GET", "/api/v1/auth/me", expected_status=200)
    assert status == 200, f"Authentication failed with token: {data}"
    user_info = data.get("data", {})
    user_email = user_info.get("email") or user_info.get("id")
    print_success(f"Authenticated successfully as: {user_email} (Role: {user_info.get('role')})")

    # 3. Resolve Project ID
    if not project_id:
        print_step("3. Resolving or Creating Target Project")
        status, data, _ = client.request("GET", "/api/v1/projects")
        projects = data.get("data", {}).get("items", []) if status == 200 else []
        if projects:
            project_id = projects[0]["id"]
            print_info(f"Using existing project: '{projects[0].get('name')}' (ID: {project_id})")
        else:
            # Create a project
            proj_name = f"e2e-secrets-project-{int(time.time())}"
            create_proj_payload = {
                "name": proj_name,
                "description": "Automated E2E testing project for secrets management",
            }
            status, data, _ = client.request("POST", "/api/v1/projects", body=create_proj_payload, expected_status=201)
            assert status == 201, f"Failed to create project: {data}"
            project_id = data.get("data", {}).get("id")
            print_success(f"Created dedicated test project: '{proj_name}' (ID: {project_id})")

    print_info(f"Active Target Project ID: {project_id}")

    secret_name = f"E2E_DB_URL_{int(time.time())}"
    secret_value = "postgres://admin_usr:super_secret_pw123@db.internal:5432/axion_prod"

    # 4. Create Secret
    print_step("4. Creating Project Secret (Zero-Plaintext Envelope)")
    create_payload = {
        "name": secret_name,
        "value": secret_value,
        "environment": "production",
        "description": "Production Postgres connection string for E2E tests",
        "tags": ["e2e", "database", "postgres"],
    }
    status, data, _ = client.request(
        "POST", f"/api/v1/projects/{project_id}/secrets", body=create_payload, expected_status=201
    )
    assert status == 201, f"Failed to create secret: {data}"
    secret_resp = data.get("data", {})
    secret_id = secret_resp.get("id")
    assert secret_id, "Missing secret ID in creation response"
    assert "value" not in secret_resp, "SECURITY LEAK: Plaintext 'value' present in create response!"
    assert "ciphertext" not in secret_resp, "LEAK: Raw ciphertext in response!"
    assert "encrypted_dek" not in secret_resp, "LEAK: DEK in response!"
    assert secret_resp.get("revision") == 1, "Initial revision must be 1"
    print_success(f"Secret '{secret_name}' created (ID: {secret_id}, Revision: 1, Zero Plaintext in response)")

    # 5. List Secret Metadata
    print_step("5. Listing Secret Metadata (Zero-Plaintext Invariant)")
    status, data, _ = client.request("GET", f"/api/v1/projects/{project_id}/secrets", expected_status=200)
    assert status == 200, f"Failed to list secrets: {data}"
    items = data.get("data", {}).get("items", [])
    found = any(s.get("id") == secret_id and s.get("name") == secret_name for s in items)
    assert found, f"Created secret {secret_id} not found in listings"
    for item in items:
        assert "value" not in item, "SECURITY LEAK: Plaintext found in secret listing item!"
    print_success(f"Secret verified in metadata list ({len(items)} secrets in project, zero plaintext confirmed)")

    # 6. Get Secret Detail
    print_step("6. Inspecting Single Secret Metadata")
    status, data, _ = client.request(
        "GET", f"/api/v1/projects/{project_id}/secrets/{secret_id}", expected_status=200
    )
    assert status == 200, f"Failed to get secret detail: {data}"
    detail = data.get("data", {})
    assert detail.get("id") == secret_id
    assert "value" not in detail, "SECURITY LEAK: Plaintext present in detail response!"
    assert detail.get("algorithm") == "AES-256-GCM"
    print_success(f"Secret detail retrieved (Algorithm: {detail.get('algorithm')}, KEK ID: {detail.get('kek_id')})")

    # 7. Update Secret In-Place
    print_step("7. In-Place Secret Update & OCC Revision Validation")
    update_payload = {
        "description": "Updated description for E2E verification",
        "tags": ["e2e", "database", "updated"],
        "revision": 1,
    }
    status, data, _ = client.request(
        "PUT", f"/api/v1/projects/{project_id}/secrets/{secret_id}", body=update_payload, expected_status=200
    )
    assert status == 200, f"Failed to update secret: {data}"
    updated = data.get("data", {})
    assert updated.get("revision") == 2, f"Revision should be bumped to 2, got {updated.get('revision')}"
    print_success(f"Secret updated in-place (Revision bumped 1 -> {updated.get('revision')})")

    # 8. Test Optimistic Concurrency Conflict (OCC)
    print_step("8. Testing Optimistic Concurrency Control (OCC 409 Conflict)")
    stale_payload = {
        "description": "This must fail with 409 Conflict because revision is stale",
        "revision": 1,  # Stale revision
    }
    status, data, _ = client.request(
        "PUT", f"/api/v1/projects/{project_id}/secrets/{secret_id}", body=stale_payload, expected_status=409
    )
    assert status == 409, f"Expected 409 Conflict on stale revision, got {status}: {data}"
    print_success("OCC Protection verified: Stale revision was rejected with HTTP 409 Conflict")

    # 9. Rotate Secret In-Place
    print_step("9. Rotating Secret Value In-Place")
    rotated_value = "postgres://admin_rotated:new_super_key_999@db.internal:5432/axion_prod"
    rotate_payload = {
        "new_value": rotated_value,
        "revision": 2,
    }
    status, data, _ = client.request(
        "POST", f"/api/v1/projects/{project_id}/secrets/{secret_id}/rotate", body=rotate_payload, expected_status=200
    )
    assert status == 200, f"Failed to rotate secret: {data}"
    rotated = data.get("data", {})
    assert rotated.get("revision") == 3, f"Revision should be 3, got {rotated.get('revision')}"
    assert rotated.get("last_rotated_at") is not None
    print_success(f"Secret rotated in-place (Revision: {rotated.get('revision')}, Last Rotated: {rotated.get('last_rotated_at')})")

    # 10. Privileged Reveal Endpoint
    print_step("10. Privileged Secret Plaintext Reveal (/reveal)")
    reveal_payload = {"reason": "E2E verification of decrypted plaintext value"}
    status, data, headers = client.request(
        "POST", f"/api/v1/projects/{project_id}/secrets/{secret_id}/reveal", body=reveal_payload, expected_status=200
    )
    assert status == 200, f"Failed to reveal secret: {data}"
    revealed = data.get("data", {})
    revealed_plaintext = revealed.get("value")
    assert revealed_plaintext == rotated_value, (
        f"Decrypted plaintext mismatch!\nExpected: {rotated_value}\nReceived: {revealed_plaintext}"
    )
    assert "no-store" in headers.get("cache-control", "").lower(), "Missing 'no-store' Cache-Control header!"
    print_success(f"Privileged reveal verified! Decrypted value matches rotated secret: '{revealed_plaintext}'")
    print_success(f"Cache-Control header verified: '{headers.get('cache-control')}'")

    # 11. Decoupled Runtime Batch Resolver (/resolve)
    print_step("11. Testing Decoupled Runtime Batch Resolver (/resolve)")
    resolve_payload = {
        "names": [secret_name, "NON_EXISTENT_KEY"],
        "environment": "production",
        "execution_id": "run-e2e-exec-001",
    }
    status, data, _ = client.request(
        "POST", f"/api/v1/projects/{project_id}/secrets/resolve", body=resolve_payload, expected_status=200
    )
    assert status == 200, f"Failed to batch resolve secrets: {data}"
    resolve_res = data.get("data", {})
    resolved_map = resolve_res.get("resolved", {})
    missing_list = resolve_res.get("missing", [])
    assert resolved_map.get(secret_name) == rotated_value, "Resolved key value mismatch!"
    assert "NON_EXISTENT_KEY" in missing_list, "Missing key was not reported in 'missing' array!"
    print_success(f"Batch resolve verified! Resolved: {list(resolved_map.keys())}, Missing: {missing_list}")

    # 12. Soft Delete Secret
    print_step("12. Soft-Deleting Secret")
    status, data, _ = client.request(
        "DELETE", f"/api/v1/projects/{project_id}/secrets/{secret_id}", expected_status=200
    )
    assert status == 200, f"Failed to delete secret: {data}"
    print_success("Secret soft-deleted successfully")

    # 13. Verify Exclusion After Deletion
    print_step("13. Verifying Secret Excluded from Active Listings")
    status, data, _ = client.request("GET", f"/api/v1/projects/{project_id}/secrets", expected_status=200)
    items_after = data.get("data", {}).get("items", [])
    assert not any(s.get("id") == secret_id for s in items_after), "Deleted secret still visible in active list!"
    print_success("Deleted secret is properly excluded from active secret listings")

    # Summary
    print(f"\n{BOLD}{GREEN}========================================================")
    print(" ALL 13 END-TO-END VERIFICATION STEPS PASSED SUCCESSFULLY! ")
    print(f"========================================================{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Pure HTTP E2E Test Suite for Axion Secrets Management (MOD-02)"
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("AXION_API_URL", "http://127.0.0.1:8000"),
        help="Base URL of running Axion API (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("AUTH_TOKEN", ""),
        help="Bearer Auth Token (Clerk JWT or dev-token-admin). If omitted, you will be prompted.",
    )
    parser.add_argument(
        "--project-id",
        default=os.environ.get("PROJECT_ID", ""),
        help="Target project ID (optional; if omitted, automatically selected or created).",
    )

    args = parser.parse_args()

    token = args.token.strip()
    if not token:
        print(f"{BOLD}{YELLOW}No auth token provided via --token or AUTH_TOKEN env.{RESET}")
        try:
            token = input(f"{BOLD}Please enter your Bearer auth token (e.g. dev-token-admin or Clerk JWT): {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not token:
        print(f"{RED}Error: Auth token is required to execute E2E tests.{RESET}")
        sys.exit(1)

    try:
        run_e2e_test(
            base_url=args.url,
            token=token,
            project_id=args.project_id.strip() or None,
        )
    except AssertionError as ae:
        print_fail(f"Assertion failed during E2E verification: {ae}")
        sys.exit(1)
    except Exception as e:
        print_fail(f"Execution error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
