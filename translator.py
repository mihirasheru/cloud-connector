from schemas.policy import Policy


def translate_to_aws(policy: Policy):
    return {
        "IpProtocol": "tcp",
        "FromPort": policy.port,
        "ToPort": policy.port,
        "IpRanges": [
            {
                "CidrIp": f"{policy.source}/32"
            }
        ]
    }


def translate_to_azure(policy: Policy):
    return {
        "name": policy.policy_name,
        "access": policy.action.capitalize(),   # allow -> Allow
        "protocol": "Tcp",
        "sourceAddressPrefix": policy.source,
        "destinationPortRange": str(policy.port),
        "priority": 100,
        "direction": "Inbound"
    }


def translate_to_pfsense(policy: Policy):
    return {
        "type": "pass" if policy.action == "allow" else "block",
        "interface": "wan",
        "protocol": "tcp",
        "source": policy.source,
        "destination": "any",
        "destination_port": str(policy.port),
        "description": policy.policy_name
    }