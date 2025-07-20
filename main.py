import argparse
import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for default values
DEFAULT_POLICY_FILE = "policies.json"
DEFAULT_USER_FILE = "users.json"
DEFAULT_CONTEXT_FILE = "context.json"

class PolicySimulator:
    """
    Simulates the impact of conditional access policies on user access.
    """

    def __init__(self, policy_file: str, user_file: str, context_file: str):
        """
        Initializes the PolicySimulator with policy, user, and context data.

        Args:
            policy_file (str): Path to the JSON file containing policies.
            user_file (str): Path to the JSON file containing user data.
            context_file (str): Path to the JSON file containing context data.
        """
        self.policy_file = policy_file
        self.user_file = user_file
        self.context_file = context_file
        self.policies = self._load_data(policy_file)
        self.users = self._load_data(user_file)
        self.context = self._load_data(context_file)


    def _load_data(self, file_path: str) -> Dict[str, Any]:
        """
        Loads data from a JSON file.

        Args:
            file_path (str): The path to the JSON file.

        Returns:
            Dict[str, Any]: The loaded data as a dictionary.  Returns an empty dictionary if an error occurs.
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            logging.info(f"Successfully loaded data from {file_path}")
            return data
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            print(f"Error: File not found: {file_path}")
            return {}
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON format in {file_path}")
            print(f"Error: Invalid JSON format in {file_path}")
            return {}
        except Exception as e:
            logging.error(f"Error loading data from {file_path}: {e}")
            print(f"Error loading data from {file_path}: {e}")
            return {}

    def simulate_access(self, user_id: str) -> bool:
        """
        Simulates access for a given user based on defined policies and context.

        Args:
            user_id (str): The ID of the user to simulate access for.

        Returns:
            bool: True if access is granted, False otherwise.
        """

        if not self.policies or not self.users or not self.context:
             print("Error: Data is not loaded.  Check that the policy, user, and context files are valid and accessible.")
             logging.error("Data is not loaded.  Check that the policy, user, and context files are valid and accessible.")
             return False

        user_data = next((user for user in self.users.get("users", []) if user["id"] == user_id), None)

        if not user_data:
            print(f"User with ID '{user_id}' not found.")
            logging.warning(f"User with ID '{user_id}' not found.")
            return False

        # Contextual information
        context_data = self.context.get("context", {})
        current_time = datetime.now().time()

        # Default access: Denied
        access_granted = False

        for policy in self.policies.get("policies", []):
            if policy.get("status") != "enabled":
                continue  # Skip disabled policies

            # Check if the policy applies to the user
            if user_id in policy.get("users", []):
                conditions = policy.get("conditions", {})

                # Check Time condition
                time_condition_met = True
                time_restrictions = conditions.get("time", {})

                if time_restrictions:
                    start_time = datetime.strptime(time_restrictions.get("start_time", "00:00"), "%H:%M").time()
                    end_time = datetime.strptime(time_restrictions.get("end_time", "23:59"), "%H:%M").time()
                    if not (start_time <= current_time <= end_time):
                        time_condition_met = False

                # Check Location condition
                location_condition_met = True
                allowed_locations = conditions.get("location", [])

                if allowed_locations:
                    user_location = context_data.get("location")
                    if user_location not in allowed_locations:
                        location_condition_met = False

                # Check Device Health Condition
                device_health_met = True
                required_device_health = conditions.get("device_health", "")

                if required_device_health:
                    current_device_health = context_data.get("device_health")
                    if current_device_health != required_device_health:
                        device_health_met = False

                # If all conditions are met, grant access based on the policy's grant control
                if time_condition_met and location_condition_met and device_health_met:
                    grant_controls = policy.get("grant_controls", {})
                    if grant_controls.get("access") == "grant":
                        access_granted = True
                        logging.info(f"Policy '{policy.get('name')}' granted access to user '{user_id}'.")
                        break  # Grant takes precedence, stop checking policies
                    else:
                        logging.info(f"Policy '{policy.get('name')}' applied but does not grant access to user '{user_id}'.")

        if not access_granted:
            logging.info(f"Access denied to user '{user_id}' based on configured policies.")
        return access_granted


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Simulate conditional access policies for users.")
    parser.add_argument("-p", "--policy_file", type=str, default=DEFAULT_POLICY_FILE,
                        help="Path to the policy JSON file. Default: policies.json")
    parser.add_argument("-u", "--user_file", type=str, default=DEFAULT_USER_FILE,
                        help="Path to the user JSON file. Default: users.json")
    parser.add_argument("-c", "--context_file", type=str, default=DEFAULT_CONTEXT_FILE,
                        help="Path to the context JSON file. Default: context.json")
    parser.add_argument("user_id", type=str,
                        help="The ID of the user to simulate access for.")

    return parser


def main() -> None:
    """
    Main function to parse arguments and run the policy simulation.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input Validation
    if not os.path.exists(args.policy_file):
        print(f"Error: Policy file not found: {args.policy_file}")
        logging.error(f"Policy file not found: {args.policy_file}")
        return
    if not os.path.exists(args.user_file):
        print(f"Error: User file not found: {args.user_file}")
        logging.error(f"User file not found: {args.user_file}")
        return
    if not os.path.exists(args.context_file):
        print(f"Error: Context file not found: {args.context_file}")
        logging.error(f"Context file not found: {args.context_file}")
        return


    simulator = PolicySimulator(args.policy_file, args.user_file, args.context_file)
    access_granted = simulator.simulate_access(args.user_id)

    if access_granted:
        print(f"Access granted to user '{args.user_id}'.")
    else:
        print(f"Access denied to user '{args.user_id}'.")


if __name__ == "__main__":
    """
    Example Usage:
    
    1.  Create three JSON files: policies.json, users.json, and context.json.
        See the example content below.
    2.  Run the script with a user ID:
        python main.py <user_id>
    
    Example policies.json:
    {
        "policies": [
            {
                "name": "Policy 1",
                "status": "enabled",
                "users": ["user1"],
                "conditions": {
                    "time": {
                        "start_time": "08:00",
                        "end_time": "18:00"
                    },
                    "location": ["USA"],
                    "device_health": "compliant"
                },
                "grant_controls": {
                    "access": "grant"
                }
            },
            {
                "name": "Policy 2",
                "status": "enabled",
                "users": ["user2"],
                "conditions": {
                    "location": ["Canada"]
                },
                "grant_controls": {
                    "access": "grant"
                }
            }
        ]
    }
    
    Example users.json:
    {
        "users": [
            {
                "id": "user1",
                "name": "John Doe"
            },
            {
                "id": "user2",
                "name": "Jane Smith"
            }
        ]
    }
    
    Example context.json:
    {
        "context": {
            "location": "USA",
            "device_health": "compliant"
        }
    }
    """
    main()