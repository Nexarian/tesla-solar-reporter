from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Tag(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TAG_SIGNATURE_TYPE: _ClassVar[Tag]
    TAG_DOMAIN: _ClassVar[Tag]
    TAG_PERSONALIZATION: _ClassVar[Tag]
    TAG_EPOCH: _ClassVar[Tag]
    TAG_EXPIRES_AT: _ClassVar[Tag]
    TAG_COUNTER: _ClassVar[Tag]
    TAG_CHALLENGE: _ClassVar[Tag]
    TAG_FLAGS: _ClassVar[Tag]
    TAG_REQUEST_HASH: _ClassVar[Tag]
    TAG_FAULT: _ClassVar[Tag]
    TAG_END: _ClassVar[Tag]

class SignatureType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIGNATURE_TYPE_AES_GCM: _ClassVar[SignatureType]
    SIGNATURE_TYPE_AES_GCM_PERSONALIZED: _ClassVar[SignatureType]
    SIGNATURE_TYPE_HMAC: _ClassVar[SignatureType]
    SIGNATURE_TYPE_RSA: _ClassVar[SignatureType]
    SIGNATURE_TYPE_HMAC_PERSONALIZED: _ClassVar[SignatureType]
    SIGNATURE_TYPE_AES_GCM_RESPONSE: _ClassVar[SignatureType]

class Domain(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DOMAIN_BROADCAST: _ClassVar[Domain]
    DOMAIN_VEHICLE_SECURITY: _ClassVar[Domain]
    DOMAIN_INFOTAINMENT: _ClassVar[Domain]
    DOMAIN_ENERGY_DEVICE: _ClassVar[Domain]

class OperationStatus_E(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OPERATIONSTATUS_OK: _ClassVar[OperationStatus_E]
    OPERATIONSTATUS_WAIT: _ClassVar[OperationStatus_E]
    OPERATIONSTATUS_ERROR: _ClassVar[OperationStatus_E]

class MessageFault_E(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESSAGEFAULT_ERROR_NONE: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_BUSY: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_TIMEOUT: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INACTIVE_KEY: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INVALID_SIGNATURE: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INSUFFICIENT_PRIVILEGES: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INVALID_DOMAINS: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INVALID_COMMAND: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_DECODING: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INTERNAL: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_WRONG_PERSONALIZATION: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_BAD_PARAMETER: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_KEYCHAIN_IS_FULL: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_INCORRECT_EPOCH: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_IV_INCORRECT_LENGTH: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_TIME_EXPIRED: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_NOT_PROVISIONED_WITH_IDENTITY: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_COULD_NOT_HASH_METADATA: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_TIME_TO_LIVE_TOO_LONG: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_REMOTE_ACCESS_DISABLED: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_REMOTE_SERVICE_ACCESS_DISABLED: _ClassVar[MessageFault_E]
    MESSAGEFAULT_ERROR_COMMAND_REQUIRES_ACCOUNT_CREDENTIALS: _ClassVar[MessageFault_E]
TAG_SIGNATURE_TYPE: Tag
TAG_DOMAIN: Tag
TAG_PERSONALIZATION: Tag
TAG_EPOCH: Tag
TAG_EXPIRES_AT: Tag
TAG_COUNTER: Tag
TAG_CHALLENGE: Tag
TAG_FLAGS: Tag
TAG_REQUEST_HASH: Tag
TAG_FAULT: Tag
TAG_END: Tag
SIGNATURE_TYPE_AES_GCM: SignatureType
SIGNATURE_TYPE_AES_GCM_PERSONALIZED: SignatureType
SIGNATURE_TYPE_HMAC: SignatureType
SIGNATURE_TYPE_RSA: SignatureType
SIGNATURE_TYPE_HMAC_PERSONALIZED: SignatureType
SIGNATURE_TYPE_AES_GCM_RESPONSE: SignatureType
DOMAIN_BROADCAST: Domain
DOMAIN_VEHICLE_SECURITY: Domain
DOMAIN_INFOTAINMENT: Domain
DOMAIN_ENERGY_DEVICE: Domain
OPERATIONSTATUS_OK: OperationStatus_E
OPERATIONSTATUS_WAIT: OperationStatus_E
OPERATIONSTATUS_ERROR: OperationStatus_E
MESSAGEFAULT_ERROR_NONE: MessageFault_E
MESSAGEFAULT_ERROR_BUSY: MessageFault_E
MESSAGEFAULT_ERROR_TIMEOUT: MessageFault_E
MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID: MessageFault_E
MESSAGEFAULT_ERROR_INACTIVE_KEY: MessageFault_E
MESSAGEFAULT_ERROR_INVALID_SIGNATURE: MessageFault_E
MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER: MessageFault_E
MESSAGEFAULT_ERROR_INSUFFICIENT_PRIVILEGES: MessageFault_E
MESSAGEFAULT_ERROR_INVALID_DOMAINS: MessageFault_E
MESSAGEFAULT_ERROR_INVALID_COMMAND: MessageFault_E
MESSAGEFAULT_ERROR_DECODING: MessageFault_E
MESSAGEFAULT_ERROR_INTERNAL: MessageFault_E
MESSAGEFAULT_ERROR_WRONG_PERSONALIZATION: MessageFault_E
MESSAGEFAULT_ERROR_BAD_PARAMETER: MessageFault_E
MESSAGEFAULT_ERROR_KEYCHAIN_IS_FULL: MessageFault_E
MESSAGEFAULT_ERROR_INCORRECT_EPOCH: MessageFault_E
MESSAGEFAULT_ERROR_IV_INCORRECT_LENGTH: MessageFault_E
MESSAGEFAULT_ERROR_TIME_EXPIRED: MessageFault_E
MESSAGEFAULT_ERROR_NOT_PROVISIONED_WITH_IDENTITY: MessageFault_E
MESSAGEFAULT_ERROR_COULD_NOT_HASH_METADATA: MessageFault_E
MESSAGEFAULT_ERROR_TIME_TO_LIVE_TOO_LONG: MessageFault_E
MESSAGEFAULT_ERROR_REMOTE_ACCESS_DISABLED: MessageFault_E
MESSAGEFAULT_ERROR_REMOTE_SERVICE_ACCESS_DISABLED: MessageFault_E
MESSAGEFAULT_ERROR_COMMAND_REQUIRES_ACCOUNT_CREDENTIALS: MessageFault_E

class Destination(_message.Message):
    __slots__ = ("domain", "routing_address")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    ROUTING_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    domain: Domain
    routing_address: bytes
    def __init__(self, domain: _Optional[_Union[Domain, str]] = ..., routing_address: _Optional[bytes] = ...) -> None: ...

class KeyIdentity(_message.Message):
    __slots__ = ("public_key", "handle")
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    HANDLE_FIELD_NUMBER: _ClassVar[int]
    public_key: bytes
    handle: int
    def __init__(self, public_key: _Optional[bytes] = ..., handle: _Optional[int] = ...) -> None: ...

class RsaSignatureData(_message.Message):
    __slots__ = ("expires_at", "signature")
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    expires_at: int
    signature: bytes
    def __init__(self, expires_at: _Optional[int] = ..., signature: _Optional[bytes] = ...) -> None: ...

class SignatureData(_message.Message):
    __slots__ = ("signer_identity", "rsa_data")
    SIGNER_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    RSA_DATA_FIELD_NUMBER: _ClassVar[int]
    signer_identity: KeyIdentity
    rsa_data: RsaSignatureData
    def __init__(self, signer_identity: _Optional[_Union[KeyIdentity, _Mapping]] = ..., rsa_data: _Optional[_Union[RsaSignatureData, _Mapping]] = ...) -> None: ...

class MessageStatus(_message.Message):
    __slots__ = ("operation_status", "signed_message_fault")
    OPERATION_STATUS_FIELD_NUMBER: _ClassVar[int]
    SIGNED_MESSAGE_FAULT_FIELD_NUMBER: _ClassVar[int]
    operation_status: OperationStatus_E
    signed_message_fault: MessageFault_E
    def __init__(self, operation_status: _Optional[_Union[OperationStatus_E, str]] = ..., signed_message_fault: _Optional[_Union[MessageFault_E, str]] = ...) -> None: ...

class RoutableMessage(_message.Message):
    __slots__ = ("to_destination", "from_destination", "protobuf_message_as_bytes", "session_info", "signed_message_status", "signature_data", "request_uuid", "uuid", "flags")
    TO_DESTINATION_FIELD_NUMBER: _ClassVar[int]
    FROM_DESTINATION_FIELD_NUMBER: _ClassVar[int]
    PROTOBUF_MESSAGE_AS_BYTES_FIELD_NUMBER: _ClassVar[int]
    SESSION_INFO_FIELD_NUMBER: _ClassVar[int]
    SIGNED_MESSAGE_STATUS_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_DATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_UUID_FIELD_NUMBER: _ClassVar[int]
    UUID_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    to_destination: Destination
    from_destination: Destination
    protobuf_message_as_bytes: bytes
    session_info: bytes
    signed_message_status: MessageStatus
    signature_data: SignatureData
    request_uuid: bytes
    uuid: bytes
    flags: int
    def __init__(self, to_destination: _Optional[_Union[Destination, _Mapping]] = ..., from_destination: _Optional[_Union[Destination, _Mapping]] = ..., protobuf_message_as_bytes: _Optional[bytes] = ..., session_info: _Optional[bytes] = ..., signed_message_status: _Optional[_Union[MessageStatus, _Mapping]] = ..., signature_data: _Optional[_Union[SignatureData, _Mapping]] = ..., request_uuid: _Optional[bytes] = ..., uuid: _Optional[bytes] = ..., flags: _Optional[int] = ...) -> None: ...
