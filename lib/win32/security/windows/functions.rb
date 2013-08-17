require 'ffi'

module Windows
  module Security
    module Functions
      extend FFI::Library

      module FFI::Library
        # Wrapper method for attach_function + private
        def attach_pfunc(*args)
          attach_function(*args)
          private args[0]
        end
      end

      typedef :ulong, :dword
      typedef :uintptr_t, :handle
      typedef :pointer, :ptr

      ffi_lib :kernel32

      enum :token_info_class, [
        :TokenUser, 1,
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
      ]

      attach_pfunc :GetCurrentProcess, [], :handle
      attach_pfunc :GetCurrentThread, [], :handle
      attach_pfunc :GetVersionExA, [:ptr], :bool
      attach_pfunc :GetLastError, [], :dword
      attach_pfunc :CloseHandle, [:dword], :bool

      ffi_lib :advapi32

      attach_pfunc :AddAccessAllowedAce, [:ptr, :dword, :dword, :ptr], :bool
      attach_pfunc :AddAce, [:ptr, :dword, :dword, :ptr, :dword], :bool
      attach_pfunc :AdjustTokenPrivileges, [:handle, :bool, :ptr, :dword, :ptr, :ptr], :bool
      attach_pfunc :AllocateAndInitializeSid,
        [:ptr, :int, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :dword, :ptr], :bool
      attach_pfunc :CheckTokenMembership, [:handle, :ptr, :ptr], :bool
      attach_pfunc :ConvertSidToStringSid, :ConvertSidToStringSidA, [:ptr, :ptr], :bool
      attach_pfunc :ConvertStringSidToSid, :ConvertStringSidToSidA, [:string, :ptr], :bool
      attach_pfunc :EqualSid, [:ptr, :ptr], :bool
      attach_pfunc :FindFirstFreeAce, [:ptr, :ptr], :bool
      attach_pfunc :GetAce, [:ptr, :dword, :pointer], :bool
      attach_pfunc :GetAclInformation, [:ptr, :ptr, :dword, :int], :bool
      attach_pfunc :GetLengthSid, [:ptr], :dword
      attach_pfunc :GetNamedSecurityInfo, :GetNamedSecurityInfoA, [:ptr, :int, :int, :ptr, :ptr, :ptr, :ptr, :ptr], :int
      attach_pfunc :GetSecurityDescriptorControl, [:ptr, :ptr, :ptr], :bool
      attach_pfunc :GetSidLengthRequired, [:uint], :dword
      attach_pfunc :GetSidSubAuthority, [:ptr, :dword], :ptr
      attach_pfunc :GetTokenInformation, [:handle, :token_info_class, :ptr, :dword, :ptr], :bool
      attach_pfunc :GetUserName, :GetUserNameA, [:ptr, :ptr], :bool
      attach_pfunc :InitializeAcl, [:ptr, :dword, :dword], :bool
      attach_pfunc :InitializeSecurityDescriptor, [:ptr, :dword], :bool
      attach_pfunc :InitializeSid, [:ptr, :ptr, :uint], :bool
      attach_pfunc :IsValidAcl, [:ptr], :bool
      attach_pfunc :IsValidSid, [:ptr], :bool
      attach_pfunc :IsWellKnownSid, [:ptr, :int], :bool
      attach_pfunc :LookupAccountName, :LookupAccountNameA,
        [:string, :string, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupAccountSid, :LookupAccountSidA,
        [:string, :ptr, :ptr, :ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupPrivilegeName, :LookupPrivilegeNameA, [:ptr, :ptr, :ptr, :ptr], :bool
      attach_pfunc :LookupPrivilegeValue, :LookupPrivilegeValueA, [:ptr, :ptr, :ptr], :bool
      attach_pfunc :OpenProcessToken, [:handle, :dword, :ptr], :bool
      attach_pfunc :OpenThreadToken, [:handle, :dword, :bool, :ptr], :bool
      attach_pfunc :SetAclInformation, [:ptr, :ptr, :dword, :int], :bool
      attach_pfunc :SetNamedSecurityInfo, :SetNamedSecurityInfoA, [:ptr, :int, :int, :ptr, :ptr, :ptr, :ptr], :ulong
      # TODO: typdef WORD SECURITY_DESCRIPTOR_CONTROL
      attach_pfunc :SetSecurityDescriptorControl, [:ptr, :ushort, :ushort], :bool
      attach_pfunc :SetSecurityDescriptorDacl, [:ptr, :bool, :ptr, :bool], :bool
    end
  end
end
