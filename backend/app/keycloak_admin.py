
import os
import httpx


KEYCLOAK_ADMIN_CLIENT_ID = os.getenv("KEYCLOAK_ADMIN_CLIENT_ID")
KEYCLOAK_ADMIN_CLIENT_SECRET = os.getenv("KEYCLOAK_ADMIN_CLIENT_SECRET")
KEYCLOAK_ADMIN_TOKEN_URL = os.getenv("KEYCLOAK_ADMIN_TOKEN_URL")


def get_admin_access_token() -> str:
    """
    Obtain an access token using the Keycloak service account.
    This token is used only by the backend.
    """

    if not all([
        KEYCLOAK_ADMIN_CLIENT_ID,
        KEYCLOAK_ADMIN_CLIENT_SECRET,
        KEYCLOAK_ADMIN_TOKEN_URL,
    ]):
        raise RuntimeError(
            "Keycloak admin service-account configuration is missing"
        )

    try:
        response = httpx.post(
            KEYCLOAK_ADMIN_TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
                "client_secret": KEYCLOAK_ADMIN_CLIENT_SECRET,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            timeout=10.0,
        )

        response.raise_for_status()

        token_data = response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise RuntimeError(
                "Keycloak did not return an access token"
            )

        return access_token

    except httpx.HTTPError as error:
        raise RuntimeError(
            "Unable to authenticate with Keycloak Admin API"
        ) from error


def create_keycloak_user(
    username: str,
    email: str,
    first_name: str,
    last_name: str,
    temporary_password: str,
) -> str:
    """
    Create a user in the CloudGuard Keycloak realm.
    Returns the newly created Keycloak user ID.
    """

    token = get_admin_access_token()

    users_url = (
        "http://keycloak:8080/admin/realms/cloudguard/users"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "username": username,
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": True,
        "emailVerified": False,
        "credentials": [
            {
                "type": "password",
                "value": temporary_password,
                "temporary": True,
            }
        ],
    }

    try:
        response = httpx.post(
            users_url,
            json=payload,
            headers=headers,
            timeout=10.0,
        )

        if response.status_code == 409:
            raise ValueError(
                "A user with this username or email already exists"
            )

        response.raise_for_status()

        location = response.headers.get("Location")

        if not location:
            raise RuntimeError(
                "Keycloak created the user but did not return its location"
            )

        return location.rstrip("/").split("/")[-1]

    except httpx.HTTPError as error:
        raise RuntimeError(
            "Failed to create user in Keycloak"
        ) from error


def assign_user_to_department(user_id: str, department: str) -> None:
    """
    Assign a Keycloak user to a CloudGuard department group.
    Department membership also grants the group's mapped realm role.
    """

    allowed_departments = {"IT", "SECURITY", "HR", "FINANCE"}
    department = department.strip().upper()

    if department not in allowed_departments:
        raise ValueError("Invalid CloudGuard department")

    token = get_admin_access_token()

    base_url = "http://keycloak:8080/admin/realms/cloudguard"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        # Retrieve department groups from Keycloak.
        groups_response = httpx.get(
            f"{base_url}/groups",
            headers=headers,
            timeout=10.0,
        )
        groups_response.raise_for_status()

        groups = groups_response.json()

        # Find the requested department group.
        group = next(
            (
                item for item in groups
                if item.get("name", "").upper() == department
            ),
            None,
        )

        if group is None:
            raise RuntimeError(
                f"Keycloak department group not found: {department}"
            )

        group_id = group["id"]

        # Add the user to the department group.
        assignment_response = httpx.put(
            f"{base_url}/users/{user_id}/groups/{group_id}",
            headers=headers,
            timeout=10.0,
        )
        assignment_response.raise_for_status()

    except httpx.HTTPError as error:
        raise RuntimeError(
            "Failed to assign user to Keycloak department group"
        ) from error


def delete_keycloak_user(user_id: str) -> None:
    """
    Delete a Keycloak user during account-creation rollback.
    """

    token = get_admin_access_token()

    users_url = (
        f"http://keycloak:8080/admin/realms/cloudguard/users/{user_id}"
    )

    headers = {
        "Authorization": f"Bearer {token}",
    }

    try:
        response = httpx.delete(
            users_url,
            headers=headers,
            timeout=10.0,
        )
        response.raise_for_status()

    except httpx.HTTPError as error:
        raise RuntimeError(
            "Failed to roll back Keycloak user creation"
        ) from error


def update_keycloak_user(
    user_id: str,
    email: str,
    first_name: str,
    last_name: str,
    enabled: bool,
) -> None:
    """
    Update employee profile information in Keycloak.
    """

    token = get_admin_access_token()

    user_url = (
        f"http://keycloak:8080/admin/realms/cloudguard/users/{user_id}"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": enabled,
    }

    try:
        response = httpx.put(
            user_url,
            json=payload,
            headers=headers,
            timeout=10.0,
        )

        response.raise_for_status()

    except httpx.HTTPError as error:
        raise RuntimeError(
            "Failed to update user in Keycloak"
        ) from error



def move_user_to_department(
    user_id: str,
    old_department: str,
    new_department: str,
) -> None:
    """
    Safely move a Keycloak user between CloudGuard department groups.
    Verifies membership and reports rollback failures explicitly.
    """

    allowed_departments = {"IT", "SECURITY", "HR", "FINANCE"}

    old_department = old_department.strip().upper()
    new_department = new_department.strip().upper()

    if old_department not in allowed_departments:
        raise ValueError("Invalid current department")

    if new_department not in allowed_departments:
        raise ValueError("Invalid target department")

    if old_department == new_department:
        return

    token = get_admin_access_token()
    base_url = "http://keycloak:8080/admin/realms/cloudguard"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        # Retrieve department groups.
        response = httpx.get(
            f"{base_url}/groups",
            headers=headers,
            timeout=10.0,
        )
        response.raise_for_status()
        groups = response.json()

        old_group = next(
            (g for g in groups
             if g.get("name", "").upper() == old_department),
            None,
        )
        new_group = next(
            (g for g in groups
             if g.get("name", "").upper() == new_department),
            None,
        )

        if not old_group or not new_group:
            raise RuntimeError("Department group not found in Keycloak")

        old_group_id = old_group["id"]
        new_group_id = new_group["id"]

        # Retrieve the employee's current group memberships.
        membership_response = httpx.get(
            f"{base_url}/users/{user_id}/groups",
            headers=headers,
            timeout=10.0,
        )
        membership_response.raise_for_status()
        memberships = membership_response.json()

        membership_ids = {group["id"] for group in memberships}

        if old_group_id not in membership_ids:
            raise RuntimeError(
                f"User is not a member of expected department: {old_department}"
            )

        if new_group_id in membership_ids:
            raise RuntimeError(
                f"User already belongs to target department: {new_department}"
            )

        # Add the new group membership first.
        add_response = httpx.put(
            f"{base_url}/users/{user_id}/groups/{new_group_id}",
            headers=headers,
            timeout=10.0,
        )
        add_response.raise_for_status()

        # Verify the new membership before removing the old one.
        verify_response = httpx.get(
            f"{base_url}/users/{user_id}/groups",
            headers=headers,
            timeout=10.0,
        )
        verify_response.raise_for_status()

        verified_ids = {
            group["id"] for group in verify_response.json()
        }

        if new_group_id not in verified_ids:
            raise RuntimeError(
                "New department membership could not be verified"
            )

        try:
            # Remove the old department membership.
            remove_response = httpx.delete(
                f"{base_url}/users/{user_id}/groups/{old_group_id}",
                headers=headers,
                timeout=10.0,
            )
            remove_response.raise_for_status()

        except Exception as original_error:
            # Attempt to undo the new membership.
            try:
                rollback_response = httpx.delete(
                    f"{base_url}/users/{user_id}/groups/{new_group_id}",
                    headers=headers,
                    timeout=10.0,
                )
                rollback_response.raise_for_status()

            except Exception as rollback_error:
                raise RuntimeError(
                    "Department transfer failed and rollback could not "
                    "be confirmed. Administrator investigation required."
                ) from rollback_error

            raise RuntimeError(
                "Could not remove the old department membership. "
                "The new membership was rolled back."
            ) from original_error

        # Verify the final membership state.
        final_response = httpx.get(
            f"{base_url}/users/{user_id}/groups",
            headers=headers,
            timeout=10.0,
        )
        final_response.raise_for_status()

        final_ids = {
            group["id"] for group in final_response.json()
        }

        if new_group_id not in final_ids or old_group_id in final_ids:
            raise RuntimeError(
                "Final department membership verification failed. "
                "Administrator investigation required."
            )

    except httpx.HTTPError as error:
        raise RuntimeError(
            "Keycloak communication failed during department transfer"
        ) from error
