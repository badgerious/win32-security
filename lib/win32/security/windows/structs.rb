require 'ffi'
require File.join(File.dirname(__FILE__), 'constants')

module Windows
  module Security
    module Structs
      extend FFI::Library

      class SID_IDENTIFIER_AUTHORITY < FFI::Struct
        layout(:Value, [:char, 6])
      end

      class OSVERSIONINFO < FFI::Struct
        layout(
          :dwOSVersionInfoSize, :ulong,
          :dwMajorVersion, :ulong,
          :dwMinorVersion, :ulong,
          :dwBuildNumber, :ulong,
          :dwPlatformId, :ulong,
          :szCSDVersion, [:char, 128]
        )
      end

      class ACE_HEADER < FFI::Struct
        layout(
          :AceType, :uchar,
          :AceFlags, :uchar,
          :AceSize, :ushort
        )
      end

      class ACCESS_ALLOWED_ACE < FFI::Struct
        layout(
          :Header, ACE_HEADER,
          :Mask, :ulong,
          :SidStart, :ulong
        )
      end

      # XXX: does this make sense?
      ACCESS_DENIED_ACE = ACCESS_ALLOWED_ACE.dup

      class ACCESS_ALLOWED_ACE2 < FFI::Struct
        layout(
          :Header, ACE_HEADER,
          :Mask, :ulong,
          :SidStart, :ulong,
          :dummy, [:uchar, 40]
        )
      end

      class ACL_STRUCT < FFI::Struct
        layout(
          :AclRevision, :uchar,
          :Sbz1, :uchar,
          :AclSize, :ushort,
          :AceCount, :ushort,
          :Sbz2, :ushort
        )
      end

      class ACL_SIZE_INFORMATION < FFI::Struct
        layout(
          :AceCount, :ulong,
          :AclBytesInUse, :ulong,
          :AclBytesFree, :ulong
        )
      end

      class LUID < FFI::Struct
        layout(
          :LowPart, :ulong,
          :HighPart, :long,
        )
      end

      class LUID_AND_ATTRIBUTES < FFI::Struct
        layout(
          :Luid, LUID,
          :Attributes, :ulong,
        )
      end

      class SECURITY_DESCRIPTOR < FFI::Struct
        layout(
          :Revision, :uchar,
          :Sbz1, :uchar,
          :Control, :ushort,
          :Owner, :pointer,
          :Group, :pointer,
          :Sacl, :pointer,
          :Dacl, :pointer
        )
      end

      class TOKEN_PRIVILEGES < FFI::Struct
        include Windows::Security::Constants
        layout(
          :PrivilegeCount, :ulong,
          :Privileges, [LUID_AND_ATTRIBUTES, ANYSIZE_ARRAY]
        )
      end
    end
  end
end
