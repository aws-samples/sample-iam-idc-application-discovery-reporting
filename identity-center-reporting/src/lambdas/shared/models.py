# Data models for IAM Identity Center Discovery Solution

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import json
import re
from enum import Enum


class ValidationError(Exception):
    """Custom exception for data validation errors"""
    pass


class InstanceType(Enum):
    """Valid instance types"""
    ORGANIZATION = "organization"
    ACCOUNT = "account"


class ApplicationStatus(Enum):
    """Valid application statuses"""
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class PrincipalType(Enum):
    """Valid principal types"""
    USER = "USER"
    GROUP = "GROUP"


class AssignmentStatus(Enum):
    """Valid assignment statuses"""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"

@dataclass
class Instance:
    """
    IAM Identity Center Instance model
    """
    instance_arn: str
    account_id: str
    region: str
    instance_type: str  # 'organization' or 'account'
    status: str
    identity_store_id: Optional[str] = None
    created_date: Optional[str] = None
    last_updated: Optional[str] = None
    discovery_metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate instance data after initialization"""
        self.validate()
    
    def validate(self) -> None:
        """Validate instance data"""
        # Validate instance ARN format
        if not self.instance_arn or not self._is_valid_instance_arn(self.instance_arn):
            raise ValidationError(f"Invalid instance ARN format: {self.instance_arn}")
        
        # Validate account ID format (12 digits)
        if not self.account_id or not re.match(r'^\d{12}$', self.account_id):
            raise ValidationError(f"Invalid account ID format: {self.account_id}")
        
        # Validate AWS region format
        if not self.region or not self._is_valid_region(self.region):
            raise ValidationError(f"Invalid AWS region format: {self.region}")
        
        # Validate instance type
        if self.instance_type not in [t.value for t in InstanceType]:
            raise ValidationError(f"Invalid instance type: {self.instance_type}")
        
        # Validate status
        if not self.status:
            raise ValidationError("Status is required")
        
        # Validate identity store ID format if provided
        if self.identity_store_id and not self._is_valid_identity_store_id(self.identity_store_id):
            raise ValidationError(f"Invalid identity store ID format: {self.identity_store_id}")
        
        # Validate timestamps if provided
        if self.created_date and not self._is_valid_iso_timestamp(self.created_date):
            raise ValidationError(f"Invalid created_date format: {self.created_date}")
        
        if self.last_updated and not self._is_valid_iso_timestamp(self.last_updated):
            raise ValidationError(f"Invalid last_updated format: {self.last_updated}")
    
    def _is_valid_instance_arn(self, arn: str) -> bool:
        """Validate instance ARN format"""
        pattern = r'^arn:aws(-[a-z]{1,5}){0,3}:sso:::instance/(sso)?ins-[a-zA-Z0-9\-.]{16}$'
        return bool(re.match(pattern, arn))
    
    def _is_valid_region(self, region: str) -> bool:
        """Validate AWS region format"""
        pattern = r'^[a-z]{2}-[a-z]+-\d{1}$'
        return bool(re.match(pattern, region))
    
    def _is_valid_identity_store_id(self, store_id: str) -> bool:
        """Validate identity store ID format"""
        pattern = r'^d-[a-f0-9]{10}$'
        return bool(re.match(pattern, store_id))
    
    def _is_valid_iso_timestamp(self, timestamp: str) -> bool:
        """Validate ISO timestamp format"""
        try:
            datetime.fromisoformat(timestamp.replace('+00:00Z', '+00:00') if '+00:00Z' in timestamp else timestamp.replace('Z', '+00:00'))
            return True
        except ValueError:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert instance to dictionary for DynamoDB storage"""
        data = asdict(self)
        # Ensure last_updated is set
        if not data.get('last_updated'):
            data['last_updated'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Instance':
        """Create instance from dictionary with validation"""
        # Create instance without validation first
        instance_data = data.copy()
        instance = cls.__new__(cls)
        for key, value in instance_data.items():
            setattr(instance, key, value)
        # Then validate
        instance.validate()
        return instance
    
    def to_json(self) -> str:
        """Convert instance to JSON string"""
        return json.dumps(self.to_dict(), default=str)

@dataclass
class Application:
    """
    IAM Identity Center Application model
    """
    application_arn: str
    instance_arn: str
    name: str
    description: Optional[str] = None
    status: str = 'ENABLED'
    application_provider_arn: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    portal_options: Optional[Dict[str, Any]] = None
    created_date: Optional[str] = None
    last_updated: Optional[str] = None
    
    def __post_init__(self):
        """Validate application data after initialization"""
        self.validate()
    
    def validate(self) -> None:
        """Validate application data"""
        # Validate application ARN format
        if not self.application_arn or not self._is_valid_application_arn(self.application_arn):
            raise ValidationError(f"Invalid application ARN format: {self.application_arn}")
        
        # Validate instance ARN format
        if not self.instance_arn or not self._is_valid_instance_arn(self.instance_arn):
            raise ValidationError(f"Invalid instance ARN format: {self.instance_arn}")
        
        # Validate application name
        if not self.name or not self.name.strip():
            raise ValidationError("Application name is required")
        
        if len(self.name) > 255:
            raise ValidationError("Application name must be 255 characters or less")
        
        # Validate status
        if self.status not in [s.value for s in ApplicationStatus]:
            raise ValidationError(f"Invalid application status: {self.status}")
        
        # Validate account ID if provided
        if self.account_id and not re.match(r'^\d{12}$', self.account_id):
            raise ValidationError(f"Invalid account ID format: {self.account_id}")
        
        # Validate region if provided
        if self.region and not self._is_valid_region(self.region):
            raise ValidationError(f"Invalid AWS region format: {self.region}")
        
        # Validate application provider ARN if provided
        if self.application_provider_arn and not self._is_valid_provider_arn(self.application_provider_arn):
            raise ValidationError(f"Invalid application provider ARN format: {self.application_provider_arn}")
        
        # Validate timestamps if provided
        if self.created_date and not self._is_valid_iso_timestamp(self.created_date):
            raise ValidationError(f"Invalid created_date format: {self.created_date}")
        
        if self.last_updated and not self._is_valid_iso_timestamp(self.last_updated):
            raise ValidationError(f"Invalid last_updated format: {self.last_updated}")
        
        # Validate description length if provided
        if self.description and len(self.description) > 1000:
            raise ValidationError("Application description must be 1000 characters or less")
    
    def _is_valid_application_arn(self, arn: str) -> bool:
        """Validate application ARN format"""
        pattern = r'^arn:aws(-[a-z]{1,5}){0,3}:sso::\d{12}:application/(sso)?ins-[a-zA-Z0-9\-.]{16}/apl-[a-zA-Z0-9]{16}$'
        return bool(re.match(pattern, arn))
    
    def _is_valid_instance_arn(self, arn: str) -> bool:
        """Validate instance ARN format"""
        pattern = r'^arn:aws(-[a-z]{1,5}){0,3}:sso:::instance/(sso)?ins-[a-zA-Z0-9\-.]{16}$'
        return bool(re.match(pattern, arn))
    
    def _is_valid_region(self, region: str) -> bool:
        """Validate AWS region format"""
        pattern = r'^[a-z]{2}-[a-z]+-\d{1}$'
        return bool(re.match(pattern, region))
    
    def _is_valid_provider_arn(self, arn: str) -> bool:
        """Validate application provider ARN format.

        AWS-managed provider ARNs can carry a multi-segment path after the
        provider id (for example
        arn:aws:sso::aws:applicationProvider/app-fe1c614acd2b4858/WIP), so allow
        one or more additional ``/<segment>`` parts.
        """
        pattern = r'^arn:aws(-[a-z]{1,5}){0,3}:sso::aws:applicationProvider/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*$'
        return bool(re.match(pattern, arn))
    
    def _is_valid_iso_timestamp(self, timestamp: str) -> bool:
        """Validate ISO timestamp format"""
        try:
            datetime.fromisoformat(timestamp.replace('+00:00Z', '+00:00') if '+00:00Z' in timestamp else timestamp.replace('Z', '+00:00'))
            return True
        except ValueError:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert application to dictionary for DynamoDB storage"""
        data = asdict(self)
        # Ensure last_updated is set
        if not data.get('last_updated'):
            data['last_updated'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Application':
        """Create application from dictionary with validation"""
        # Create application without validation first
        app_data = data.copy()
        application = cls.__new__(cls)
        for key, value in app_data.items():
            setattr(application, key, value)
        # Then validate
        application.validate()
        return application
    
    def to_json(self) -> str:
        """Convert application to JSON string"""
        return json.dumps(self.to_dict(), default=str)

@dataclass
class Assignment:
    """
    IAM Identity Center Assignment model
    """
    assignment_id: str
    application_arn: str
    principal_id: str
    principal_type: str  # 'USER' or 'GROUP'
    principal_name: str
    permission_set_arn: Optional[str] = None
    permission_set_name: Optional[str] = None
    account_id: Optional[str] = None
    instance_arn: Optional[str] = None
    assignment_status: str = 'ACTIVE'
    last_updated: Optional[str] = None
    # Enhanced metadata fields
    principal_display_name: Optional[str] = None
    principal_email: Optional[str] = None
    matched: Optional[str] = None  # 'Yes', 'No', or 'Unknown' for group assignments
    # Last-accessed tracking fields (populated by access-tracker Lambda)
    last_accessed: Optional[str] = None              # ISO timestamp from CloudTrail
    last_accessed_source: Optional[str] = None       # 'cloudtrail' or 'manual'
    days_since_last_access: Optional[int] = None     # Calculated days since last access
    stale_assignment: Optional[bool] = None          # True if exceeds stale_threshold_days
    stale_threshold_days: Optional[int] = None       # Threshold used for stale calculation
    access_tracking_updated: Optional[str] = None    # When access tracking was last updated
    
    def __post_init__(self):
        """Validate assignment data after initialization"""
        self.validate()
    
    def validate(self) -> None:
        """Validate assignment data"""
        # Validate assignment ID format
        if not self.assignment_id or not self.assignment_id.strip():
            raise ValidationError("Assignment ID is required")
        
        # Validate application ARN format
        if not self.application_arn or not self._is_valid_application_arn(self.application_arn):
            raise ValidationError(f"Invalid application ARN format: {self.application_arn}")
        
        # Validate principal ID
        if not self.principal_id or not self.principal_id.strip():
            raise ValidationError("Principal ID is required")
        
        # Validate principal type
        if self.principal_type not in [t.value for t in PrincipalType]:
            raise ValidationError(f"Invalid principal type: {self.principal_type}")
        
        # Validate principal name
        if not self.principal_name or not self.principal_name.strip():
            raise ValidationError("Principal name is required")
        
        if len(self.principal_name) > 255:
            raise ValidationError("Principal name must be 255 characters or less")
        
        # Validate assignment status
        if self.assignment_status not in [s.value for s in AssignmentStatus]:
            raise ValidationError(f"Invalid assignment status: {self.assignment_status}")
        
        # Validate account ID if provided
        if self.account_id and not re.match(r'^\d{12}$', self.account_id):
            raise ValidationError(f"Invalid account ID format: {self.account_id}")
        
        # Validate instance ARN if provided
        if self.instance_arn and not self._is_valid_instance_arn(self.instance_arn):
            raise ValidationError(f"Invalid instance ARN format: {self.instance_arn}")
        
        # Validate permission set ARN if provided
        if self.permission_set_arn and not self._is_valid_permission_set_arn(self.permission_set_arn):
            raise ValidationError(f"Invalid permission set ARN format: {self.permission_set_arn}")
        
        # Validate permission set name if provided
        if self.permission_set_name and len(self.permission_set_name) > 255:
            raise ValidationError("Permission set name must be 255 characters or less")
        
        # Validate timestamp if provided
        if self.last_updated and not self._is_valid_iso_timestamp(self.last_updated):
            raise ValidationError(f"Invalid last_updated format: {self.last_updated}")
        
        # Validate principal ID format based on type
        if self.principal_type == PrincipalType.USER.value:
            if not self._is_valid_user_id(self.principal_id):
                raise ValidationError(f"Invalid user ID format: {self.principal_id}")
        elif self.principal_type == PrincipalType.GROUP.value:
            if not self._is_valid_group_id(self.principal_id):
                raise ValidationError(f"Invalid group ID format: {self.principal_id}")
    
    def _is_valid_application_arn(self, arn: str) -> bool:
        """Validate application ARN format"""
        pattern = r'^arn:aws(-[a-z]{1,5}){0,3}:sso::\d{12}:application/(sso)?ins-[a-zA-Z0-9\-.]{16}/apl-[a-zA-Z0-9]{16}$'
        return bool(re.match(pattern, arn))
    
    def _is_valid_instance_arn(self, arn: str) -> bool:
        """Validate instance ARN format"""
        pattern = r'^arn:aws(-[a-z]{1,5}){0,3}:sso:::instance/(sso)?ins-[a-zA-Z0-9\-.]{16}$'
        return bool(re.match(pattern, arn))
    
    def _is_valid_permission_set_arn(self, arn: str) -> bool:
        """Validate permission set ARN format"""
        pattern = r'^arn:aws(-[a-z]{1,5}){0,3}:sso:::permissionSet/(sso)?ins-[a-zA-Z0-9\-.]{16}/ps-[a-zA-Z0-9]{16}$'
        return bool(re.match(pattern, arn))
    
    def _is_valid_user_id(self, user_id: str) -> bool:
        """Validate user ID format"""
        # User IDs can be UUIDs or other formats depending on identity provider
        pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$|^user-[a-f0-9]{16}$'
        return bool(re.match(pattern, user_id))
    
    def _is_valid_group_id(self, group_id: str) -> bool:
        """Validate group ID format"""
        # Group IDs can be UUIDs or other formats depending on identity provider
        pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$|^group-[a-f0-9]{16}$'
        return bool(re.match(pattern, group_id))
    
    def _is_valid_iso_timestamp(self, timestamp: str) -> bool:
        """Validate ISO timestamp format"""
        try:
            datetime.fromisoformat(timestamp.replace('+00:00Z', '+00:00') if '+00:00Z' in timestamp else timestamp.replace('Z', '+00:00'))
            return True
        except ValueError:
            return False
    
    @classmethod
    def create_assignment_id(cls, application_arn: str, principal_id: str) -> str:
        """Create a composite assignment ID"""
        app_id = application_arn.split('/')[-1]  # Extract application ID from ARN
        return f"{app_id}#{principal_id}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert assignment to dictionary for DynamoDB storage"""
        data = asdict(self)
        # Ensure last_updated is set
        if not data.get('last_updated'):
            data['last_updated'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        # Include matched field (will be None or string)
        if 'matched' not in data:
            data['matched'] = None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Assignment':
        """Create assignment from dictionary with validation"""
        # Create assignment without validation first
        assignment_data = data.copy()
        assignment = cls.__new__(cls)
        for key, value in assignment_data.items():
            setattr(assignment, key, value)
        # Ensure matched field exists (set to None if not present)
        if not hasattr(assignment, 'matched'):
            assignment.matched = None
        # Then validate
        assignment.validate()
        return assignment
    
    def to_json(self) -> str:
        """Convert assignment to JSON string"""
        return json.dumps(self.to_dict(), default=str)

class DiscoveryResult:
    """
    Container for discovery operation results
    """
    def __init__(self, success: bool = True, message: str = "", data: Optional[List[Any]] = None, errors: Optional[List[str]] = None):
        self.success = success
        self.message = message
        self.data = data or []
        self.errors = errors or []
        self.timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    def add_error(self, error: str):
        """Add an error to the result"""
        self.errors.append(error)
        if self.success:
            self.success = False
    
    def add_data(self, item: Any):
        """Add a data item to the result"""
        self.data.append(item)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'success': self.success,
            'message': self.message,
            'data': self.data,
            'errors': self.errors,
            'timestamp': self.timestamp,
            'count': len(self.data)
        }