"""
Policy Schema

We use Pydantic to validate the security policies received
from User 11 before they are deployed to AWS, Azure or pfSense.

BaseModel is a class provided by the Pydantic library.
By inheriting from BaseModel, our Policy class automatically
gets data validation and type checking.
"""

"""
Pydantic Model Syntax

Basic syntax:
    field_name: DataType

When extra validation is required:
    field_name: DataType = Field(validation_rules)

Field() is optional.
We use it whenever we need additional constraints,
such as validating port numbers.
"""

from typing import Literal
from typing_extensions import Annotated

from pydantic import BaseModel, Field, StringConstraints


class Policy(BaseModel):

    # Unique identifier for the security policy.
    # This is assigned by User 11 and is used to
    # uniquely identify each policy across the system.
    id: int

    # Name of the security policy.
    # Must not be empty or contain only spaces.
    policy_name: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=100
        )
    ]

    # Resource that the rule protects.
    # Examples:
    # "web-server"
    # "database"
    # "transactions-api"
    resource: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=100
        )
    ]

    # Supported policy actions.
    # These are generic actions which can later be translated
    # into AWS, Azure or pfSense specific rules.
    action: Literal["allow", "deny"]

    # Source of the traffic/request.
    #
    # This intentionally accepts ANY non-empty string because
    # the source may be:
    #
    # • IP Address
    #       192.168.1.10
    #
    # • CIDR Block
    #       10.0.0.0/24
    #
    # • Internet
    #       0.0.0.0/0
    #
    # • Hostname
    #       web-server-01
    #
    # • User Group
    #       employees
    #
    # • VPN
    #       Corporate VPN
    #
    # Validation of whether it is an IP, CIDR or group
    # will be handled later by the deployment logic.
    source: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=100
        )
    ]

    # Network port.
    #
    # ge = Greater than or Equal to
    # le = Less than or Equal to
    #
    # Valid range:
    # 1 - 65535
    port: int = Field(
        ge=1,
        le=65535,
        description="Destination network port"
    )