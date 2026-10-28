"""
TRUSTMESH Administrative Provisioning CLI (Phase 3)
Allows initial provisioning of an administrative user account
without hard-coding plaintext credentials in source code.

Usage:
    python create_admin.py admin@trustmesh.local "System Administrator" "StrongPassword123!"
"""

import sys
from werkzeug.security import generate_password_hash
from database import create_user, get_user_by_email, init_db, log_audit_event


def provision_admin(email: str, display_name: str, password: str) -> None:
    # Ensure database is initialized and migrated
    init_db()

    email_clean = email.strip().lower()
    existing = get_user_by_email(email_clean)
    if existing:
        print(f"[!] Error: An account with email '{email_clean}' already exists (User ID: {existing['user_id']}).")
        sys.exit(1)

    if len(password) < 8:
        print("[!] Error: Password must be at least 8 characters long.")
        sys.exit(1)

    password_hash = generate_password_hash(password)
    user_id = create_user(
        display_name=display_name.strip(),
        email=email_clean,
        password_hash=password_hash,
        role_id=2,  # Admin role
        account_status="ACTIVE"
    )

    log_audit_event(user_id, "ADMIN_PROVISIONED", "SUCCESS", f"Admin account provisioned for {email_clean}")
    print(f"[+] Administrator account created successfully! User ID: {user_id}, Email: {email_clean}")


if __name__ == "__main__":
    if len(sys.argv) == 4:
        provision_admin(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("TRUSTMESH Admin Account Provisioning")
        print("-------------------------------------")
        try:
            in_email = input("Admin Email: ").strip()
            in_name = input("Display Name: ").strip()
            in_pass = input("Password (min 8 chars): ").strip()
            if in_email and in_name and in_pass:
                provision_admin(in_email, in_name, in_pass)
            else:
                print("[!] All fields are required.")
        except KeyboardInterrupt:
            print("\nAborted.")
