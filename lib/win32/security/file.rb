require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')
require File.join(File.dirname(__FILE__), 'privilege')

module Win32
  class Security
    class File
      include Windows::Security::Constants
      include Windows::Security::Functions 
      include Windows::Security::Structs
      
      # version of File class
      VERSION = '0.1.0'

      def initialize(path)
        ::File.exists?(path) or raise ArgumentError, "#{path} does not exist"
        @path = path
        ppDacl = FFI::MemoryPointer.new :pointer
        ppsidOwner = FFI::MemoryPointer.new :pointer
        ppsidGroup = FFI::MemoryPointer.new :pointer
        ppSD = FFI::MemoryPointer.new :pointer
        GetNamedSecurityInfo(path,
                             SE_FILE_OBJECT, 
                             OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, 
                             ppsidOwner,
                             ppsidGroup,
                             ppDacl,
                             nil, 
                             ppSD)
        @dacl = ACL.new(ACL_STRUCT.new(ppDacl.read_pointer))
        length = GetLengthSid(ppsidOwner.read_pointer)
        @owner = SID.new(ppsidOwner.read_pointer.read_string(length))
        length = GetLengthSid(ppsidGroup.read_pointer)
        @group = SID.new(ppsidGroup.read_pointer.read_string(length))
        @security_descriptor = SECURITY_DESCRIPTOR.new(ppSD.read_pointer)
      end

      # SID of the file's owner
      attr_reader :owner

      # SID of the file's primary group. XXX: is this useful?
      attr_reader :group

      # An ACL object for the file's DACL
      attr_reader :dacl

      # An ACL object for the file's SACL
      attr_reader :sacl

      # The raw SECURITY_DESCRIPTOR struct
      attr_reader :security_descriptor

      # @param [Win32::Security::ACL] The new DACL
      def dacl=(acl)
        acl.class == ACL or raise ArgumentError, "Invalid class #{acl.class} for acl"
        @dacl = acl
        SetNamedSecurityInfo(@path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, @dacl.acl.to_ptr, nil)
      end

      def owner=(sid)
        sid.class == SID or raise ArgumentError, "Invalid class #{sid.class} for sid"
        unless sid == owner
          unless (err = SetNamedSecurityInfo(@path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, sid.sid, nil, nil, nil)) == 0
            if FFI::errno == ERROR_INVALID_OWNER
              privs = []
              if Privilege.get_privileges.include?(SE_RESTORE_NAME)
                privs << SE_RESTORE_NAME
              end
              if Privilege.get_privileges.include?(SE_TAKE_OWNERSHIP_NAME) && sid == SID.new
                privs << SE_TAKE_OWNERSHIP_NAME
              end
              Privilege.with_privileges(*privs) do
                unless SetNamedSecurityInfo(@path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, sid.sid, nil, nil, nil) == 0
                  raise SystemCallError.new("SetNamedSecurityInfo", FFI::errno)
                end
              end
            else
              raise SystemCallError.new("SetNamedSecurityInfo", err)
            end
          end
          @owner = sid
        end
      end

      # http://msdn.microsoft.com/en-us/library/windows/desktop/aa379620%28v=vs.85%29.aspx
      # http://stackoverflow.com/questions/12338711/error-access-denied-setting-file-owner
      def takeown
        sid = SID.new
        self.owner = SID.new
      end
    end
  end
end
