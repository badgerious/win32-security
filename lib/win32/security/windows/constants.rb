require File.join(File.dirname(__FILE__), 'functions')

module Windows
  module Security
    module Constants
      # Translates a bunch of bits into a list of constants
      # from the given module.
      def self.bits_to_constants(modulename, bits)
        constants = []
        modulename.constants.each do |const|
          if bits & modulename.const_get(const) == modulename.const_get(const)
            constants << const
          end
        end
        # If there are overlapping constants, remove those
        # with fewer bits set (more bits means more general,
        # which is probably what the user wants to see). 
        constants.reject! do |const|
          const = modulename.const_get(const)
          constants.any? do |otherconst|
            otherconst = modulename.const_get(otherconst)
            const & otherconst == const && otherconst.to_s(2).count('1') > const.to_s(2).count('1')
          end
        end
        constants
      end

      module GROUP_TOKEN_ACCESS_RIGHTS
        TOKEN_ASSIGN_PRIMARY    = 0x0001
        TOKEN_DUPLICATE         = 0x0002
        TOKEN_IMPERSONATE       = 0x0004
        TOKEN_QUERY             = 0x0008
        TOKEN_QUERY_SOURCE      = 0x0010
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_ADJUST_GROUPS     = 0x0040
        TOKEN_ADJUST_DEFAULT    = 0x0080
        TOKEN_ADJUST_SESSIONID  = 0x0100
      end
      include GROUP_TOKEN_ACCESS_RIGHTS

      module GROUP_ACE_FLAGS
        OBJECT_INHERIT_ACE       = 0x1
        CONTAINER_INHERIT_ACE    = 0x2
        NO_PROPAGATE_INHERIT_ACE = 0x4
        INHERIT_ONLY_ACE         = 0x8
        INHERITED_ACE            = 0x10
        VALID_INHERIT_FLAGS      = 0x1F
      end
      include GROUP_ACE_FLAGS
      
      module GROUP_ACE_TYPES
        # TODO: fill in more?
        ACCESS_ALLOWED_ACE_TYPE = 0x0
        ACCESS_DENIED_ACE_TYPE  = 0x1
      end
      include GROUP_ACE_TYPES

      # ACL Revisions

      ACL_REVISION1 = 1
      ACL_REVISION  = 2
      ACL_REVISION2 = 2
      ACL_REVISION3 = 3
      ACL_REVISION4 = 4

      # ACL Information Classes

      AclRevisionInformation = 1
      AclSizeInformation     = 2

			# Access types
      
			DELETE       = 0x00010000
			READ_CONTROL = 0x00020000
			WRITE_DAC    = 0x00040000
			WRITE_OWNER  = 0x00080000
			SYNCHRONIZE  = 0x00100000
			
			STANDARD_RIGHTS_REQUIRED = 0x000F0000
			STANDARD_RIGHTS_READ     = READ_CONTROL
			STANDARD_RIGHTS_WRITE    = READ_CONTROL
			STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
			STANDARD_RIGHTS_ALL      = 0x001F0000
			SPECIFIC_RIGHTS_ALL      = 0x0000FFFF

      module GROUP_FILE_ACCESS_RIGHTS
        FILE_READ_DATA            = 0x0001
        FILE_LIST_DIRECTORY       = 0x0001
        FILE_WRITE_DATA           = 0x0002
        FILE_ADD_FILE             = 0x0002
        FILE_APPEND_DATA          = 0x0004
        FILE_ADD_SUBDIRECTORY     = 0x0004
        FILE_CREATE_PIPE_INSTANCE = 0x0004
        FILE_READ_EA              = 0x0008
        FILE_WRITE_EA             = 0x0010
        FILE_EXECUTE              = 0x0020
        FILE_TRAVERSE             = 0x0020
        FILE_DELETE_CHILD         = 0x0040
        FILE_READ_ATTRIBUTES      = 0x0080
        FILE_WRITE_ATTRIBUTES     = 0x0100

        FILE_GENERIC_READ    = STANDARD_RIGHTS_READ | 
                               FILE_READ_DATA | 
                               FILE_READ_ATTRIBUTES | 
                               FILE_READ_EA | 
                               SYNCHRONIZE
        FILE_GENERIC_WRITE   = STANDARD_RIGHTS_WRITE | 
                               FILE_WRITE_DATA | 
                               FILE_WRITE_ATTRIBUTES | 
                               FILE_WRITE_EA | 
                               FILE_APPEND_DATA | 
                               SYNCHRONIZE
        FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | 
                               FILE_READ_ATTRIBUTES | 
                               FILE_EXECUTE | 
                               SYNCHRONIZE

        FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF
      end
      include GROUP_FILE_ACCESS_RIGHTS

      module GROUP_SE_OBJECT_TYPES
        SE_UNKNOWN_OBJECT_TYPE     = 0
        SE_FILE_OBJECT             = 1
        SE_SERVICE                 = 2
        SE_PRINTER                 = 3
        SE_REGISTRY_KEY            = 4
        SE_LMSHARE                 = 5
        SE_KERNEL_OBJECT           = 6
        SE_WINDOW_OBJECT           = 7
        SE_DS_OBJECT               = 8
        SE_DS_OBJECT_ALL           = 9
        SE_PROVIDER_DEFINED_OBJECT = 10
        SE_WMIGUID_OBJECT          = 11
        SE_REGISTRY_WOW64_32KEY    = 12
      end
      include GROUP_SE_OBJECT_TYPES

      # SECURITY_INFORMATION flags

      ATTRIBUTE_SECURITY_INFORMATION        = 0x00000020
      BACKUP_SECURITY_INFORMATION           = 0x00010000
      DACL_SECURITY_INFORMATION             = 0x00000004
      GROUP_SECURITY_INFORMATION            = 0x00000002
      LABEL_SECURITY_INFORMATION            = 0x00000010
      OWNER_SECURITY_INFORMATION            = 0x00000001
      PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
      PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
      SACL_SECURITY_INFORMATION             = 0x00000008
      SCOPE_SECURITY_INFORMATION            = 0x00000040
      UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
      UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000

      # Identifier Authorities

      SECURITY_NULL_SID_AUTHORITY         = 0
      SECURITY_WORLD_SID_AUTHORITY        = 1
      SECURITY_LOCAL_SID_AUTHORITY        = 2
      SECURITY_CREATOR_SID_AUTHORITY      = 3
      SECURITY_NON_UNIQUE_AUTHORITY       = 4
      SECURITY_NT_AUTHORITY               = 5
      SECURITY_RESOURCE_MANAGER_AUTHORITY = 9

      # Subauthorities

      SECURITY_NULL_RID                 = 0x00000000
      SECURITY_WORLD_RID                = 0x00000000
      SECURITY_LOCAL_RID                = 0x00000000
      SECURITY_CREATOR_OWNER_RID        = 0x00000000
      SECURITY_CREATOR_GROUP_RID        = 0x00000001
      SECURITY_CREATOR_OWNER_SERVER_RID = 0x00000002
      SECURITY_CREATOR_GROUP_SERVER_RID = 0x00000003
      SECURITY_DIALUP_RID               = 0x00000001
      SECURITY_NETWORK_RID              = 0x00000002
      SECURITY_BATCH_RID                = 0x00000003
      SECURITY_INTERACTIVE_RID          = 0x00000004
      SECURITY_LOGON_IDS_RID            = 0x00000005
      SECURITY_LOGON_IDS_RID_COUNT      = 3
      SECURITY_SERVICE_RID              = 0x00000006
      SECURITY_ANONYMOUS_LOGON_RID      = 0x00000007
      SECURITY_PROXY_RID                = 0x00000008

      SECURITY_ENTERPRISE_CONTROLLERS_RID   = 0x00000009
      SECURITY_SERVER_LOGON_RID             = SECURITY_ENTERPRISE_CONTROLLERS_RID
      SECURITY_PRINCIPAL_SELF_RID           = 0x0000000A
      SECURITY_AUTHENTICATED_USER_RID       = 0x0000000B
      SECURITY_RESTRICTED_CODE_RID          = 0x0000000C
      SECURITY_TERMINAL_SERVER_RID          = 0x0000000D
      SECURITY_REMOTE_LOGON_RID             = 0x0000000E
      SECURITY_THIS_ORGANIZATION_RID        = 0x0000000F
      SECURITY_LOCAL_SYSTEM_RID             = 0x00000012
      SECURITY_LOCAL_SERVICE_RID            = 0x00000013
      SECURITY_NETWORK_SERVICE_RID          = 0x00000014
      SECURITY_NT_NON_UNIQUE                = 0x00000015
      SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT = 3

      SECURITY_BUILTIN_DOMAIN_RID     = 0x00000020
      SECURITY_PACKAGE_BASE_RID       = 0x00000040
      SECURITY_PACKAGE_RID_COUNT      = 2
      SECURITY_PACKAGE_NTLM_RID       = 0x0000000A
      SECURITY_PACKAGE_SCHANNEL_RID   = 0x0000000E
      SECURITY_PACKAGE_DIGEST_RID     = 0x00000015
      SECURITY_MAX_ALWAYS_FILTERED    = 0x000003E7
      SECURITY_MIN_NEVER_FILTERED     = 0x000003E8

      SECURITY_OTHER_ORGANIZATION_RID     = 0x000003E8
      FOREST_USER_RID_MAX                 = 0x000001F3
      DOMAIN_USER_RID_ADMIN               = 0x000001F4
      DOMAIN_USER_RID_GUEST               = 0x000001F5
      DOMAIN_USER_RID_KRBTGT              = 0x000001F6
      DOMAIN_USER_RID_MAX                 = 0x000003E7
      DOMAIN_GROUP_RID_ADMINS             = 0x00000200
      DOMAIN_GROUP_RID_USERS              = 0x00000201
      DOMAIN_GROUP_RID_GUESTS             = 0x00000202
      DOMAIN_GROUP_RID_COMPUTERS          = 0x00000203
      DOMAIN_GROUP_RID_CONTROLLERS        = 0x00000204
      DOMAIN_GROUP_RID_CERT_ADMINS        = 0x00000205
      DOMAIN_GROUP_RID_SCHEMA_ADMINS      = 0x00000206
      DOMAIN_GROUP_RID_ENTERPRISE_ADMINS  = 0x00000207
      DOMAIN_GROUP_RID_POLICY_ADMINS      = 0x00000208
      DOMAIN_ALIAS_RID_ADMINS             = 0x00000220
      DOMAIN_ALIAS_RID_USERS              = 0x00000221
      DOMAIN_ALIAS_RID_GUESTS             = 0x00000222
      DOMAIN_ALIAS_RID_POWER_USERS        = 0x00000223
      DOMAIN_ALIAS_RID_ACCOUNT_OPS        = 0x00000224
      DOMAIN_ALIAS_RID_SYSTEM_OPS         = 0x00000225
      DOMAIN_ALIAS_RID_PRINT_OPS          = 0x00000226
      DOMAIN_ALIAS_RID_BACKUP_OPS         = 0x00000227
      DOMAIN_ALIAS_RID_REPLICATOR         = 0x00000228
      DOMAIN_ALIAS_RID_RAS_SERVERS        = 0x00000229

      DOMAIN_ALIAS_RID_PREW2KCOMPACCESS               = 0x0000022A
      DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS           = 0x0000022B
      DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS      = 0x0000022C
      DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D
      DOMAIN_ALIAS_RID_MONITORING_USERS               = 0x0000022E
      DOMAIN_ALIAS_RID_LOGGING_USERS                  = 0x0000022F
      DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS            = 0x00000230
      DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS             = 0x00000231
      DOMAIN_ALIAS_RID_DCOM_USERS                     = 0x00000232

      # SID types

      SidTypeUser           = 1
      SidTypeGroup          = 2
      SidTypeDomain         = 3
      SidTypeAlias          = 4
      SidTypeWellKnownGroup = 5
      SidTypeDeletedAccount = 6
      SidTypeInvalid        = 7
      SidTypeUnknown        = 8
      SidTypeComputer       = 9

      # Misc

      MAXDWORD = 2 ** (8 * Functions.find_type(:dword).size ) - 1
      ANYSIZE_ARRAY = 1

      # Security descriptor revisions

      SECURITY_DESCRIPTOR_REVISION  = 1
      SECURITY_DESCRIPTOR_REVISION1 = 1

      module GROUP_SECURITY_DESCRIPTOR_CONTROL_FLAGS
        SE_OWNER_DEFAULTED       = 0x0001
        SE_GROUP_DEFAULTED       = 0x0002
        SE_DACL_PRESENT          = 0x0004
        SE_DACL_DEFAULTED        = 0x0008
        SE_SACL_PRESENT          = 0x0010
        SE_SACL_DEFAULTED        = 0x0020
        SE_DACL_AUTO_INHERIT_REQ = 0x0100
        SE_SACL_AUTO_INHERIT_REQ = 0x0200
        SE_DACL_AUTO_INHERITED   = 0x0400
        SE_SACL_AUTO_INHERITED   = 0x0800
        SE_DACL_PROTECTED        = 0x1000
        SE_SACL_PROTECTED        = 0x2000
        SE_RM_CONTROL_VALID      = 0x4000
        SE_SELF_RELATIVE         = 0x8000
      end
      include GROUP_SECURITY_DESCRIPTOR_CONTROL_FLAGS

      module GROUP_NT_PRIVILEGES
        SE_CREATE_TOKEN_NAME           = "SeCreateTokenPrivilege"
        SE_ASSIGNPRIMARYTOKEN_NAME     = "SeAssignPrimaryTokenPrivilege"
        SE_LOCK_MEMORY_NAME            = "SeLockMemoryPrivilege"
        SE_INCREASE_QUOTA_NAME         = "SeIncreaseQuotaPrivilege"
        SE_UNSOLICITED_INPUT_NAME      = "SeUnsolicitedInputPrivilege"
        SE_MACHINE_ACCOUNT_NAME        = "SeMachineAccountPrivilege"
        SE_TCB_NAME                    = "SeTcbPrivilege"
        SE_SECURITY_NAME               = "SeSecurityPrivilege"
        SE_TAKE_OWNERSHIP_NAME         = "SeTakeOwnershipPrivilege"
        SE_LOAD_DRIVER_NAME            = "SeLoadDriverPrivilege"
        SE_SYSTEM_PROFILE_NAME         = "SeSystemProfilePrivilege"
        SE_SYSTEMTIME_NAME             = "SeSystemtimePrivilege"
        SE_PROF_SINGLE_PROCESS_NAME    = "SeProfileSingleProcessPrivilege"
        SE_INC_BASE_PRIORITY_NAME      = "SeIncreaseBasePriorityPrivilege"
        SE_CREATE_PAGEFILE_NAME        = "SeCreatePagefilePrivilege"
        SE_CREATE_PERMANENT_NAME       = "SeCreatePermanentPrivilege"
        SE_BACKUP_NAME                 = "SeBackupPrivilege"
        SE_RESTORE_NAME                = "SeRestorePrivilege"
        SE_SHUTDOWN_NAME               = "SeShutdownPrivilege"
        SE_DEBUG_NAME                  = "SeDebugPrivilege"
        SE_AUDIT_NAME                  = "SeAuditPrivilege"
        SE_SYSTEM_ENVIRONMENT_NAME     = "SeSystemEnvironmentPrivilege"
        SE_CHANGE_NOTIFY_NAME          = "SeChangeNotifyPrivilege"
        SE_REMOTE_SHUTDOWN_NAME        = "SeRemoteShutdownPrivilege"
        SE_UNDOCK_NAME                 = "SeUndockPrivilege"
        SE_SYNC_AGENT_NAME             = "SeSyncAgentPrivilege"
        SE_ENABLE_DELEGATION_NAME      = "SeEnableDelegationPrivilege"
        SE_MANAGE_VOLUME_NAME          = "SeManageVolumePrivilege"
        SE_IMPERSONATE_NAME            = "SeImpersonatePrivilege"
        SE_CREATE_GLOBAL_NAME          = "SeCreateGlobalPrivilege"
        SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege"
        SE_RELABEL_NAME                = "SeRelabelPrivilege"
        SE_INC_WORKING_SET_NAME        = "SeIncreaseWorkingSetPrivilege"
        SE_TIME_ZONE_NAME              = "SeTimeZonePrivilege"
        SE_CREATE_SYMBOLIC_LINK_NAME   = "SeCreateSymbolicLinkPrivilege"
      end
      include GROUP_NT_PRIVILEGES

      module GROUP_PRIVILEGE_ATTRIBUTES
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
        SE_PRIVILEGE_ENABLED            = 0x00000002
        SE_PRIVILEGE_REMOVED            = 0X00000004
        SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
      end
      include GROUP_PRIVILEGE_ATTRIBUTES

      module GROUP_TOKEN_INFORMATION_CLASS
        [
        :TokenUser,
        :TokenGroups,
        :TokenPrivileges,
        :TokenOwner,
        :TokenPrimaryGroup,
        :TokenDefaultDacl,
        :TokenSource,
        :TokenType,
        :TokenImpersonationLevel,
        :TokenStatistics,
        :TokenRestrictedSids,
        :TokenSessionId,
        :TokenGroupsAndPrivileges,
        :TokenSessionReference,
        :TokenSandBoxInert,
        :TokenAuditPolicy,
        :TokenOrigin,
        :TokenElevationType,
        :TokenLinkedToken,
        :TokenElevation,
        :TokenHasRestrictions,
        :TokenAccessInformation,
        :TokenVirtualizationAllowed,
        :TokenVirtualizationEnabled,
        :TokenIntegrityLevel,
        :TokenUIAccess,
        :TokenMandatoryPolicy,
        :TokenLogonSid,
        :TokenIsAppContainer,
        :TokenCapabilities,
        :TokenAppContainerSid,
        :TokenAppContainerNumber,
        :TokenUserClaimAttributes,
        :TokenDeviceClaimAttributes,
        :TokenRestrictedUserClaimAttributes,
        :TokenRestrictedDeviceClaimAttributes,
        :TokenDeviceGroups,
        :TokenRestrictedDeviceGroups,
        :TokenSecurityAttributes,
        :TokenIsRestricted,
        :MaxTokenInfoClass
        ].each_with_index do |const, index|
          const_set(const, index + 1)
        end
      end
      include GROUP_TOKEN_INFORMATION_CLASS

      module GROUP_ERRORS
        ERROR_INVALID_OWNER = 1307
      end
      include GROUP_ERRORS
    end
  end
end
