require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

module Win32
  class Security
    class Privilege
      include Windows::Security::Constants
      include Windows::Security::Functions
      include Windows::Security::Structs
      extend Windows::Security::Functions

      def self.with_privileges(*privs, &block)
        changedPrivs = enable_privileges(*privs)
        block.call
      ensure
        disable_privileges(*changedPrivs.keys) if changedPrivs
      end

      def self.enable_privileges(*privs)
        set_privileges(SE_PRIVILEGE_ENABLED, privs)
      end

      def self.disable_privileges(*privs)
        set_privileges(0, privs)
      end

      # Returns a Hash with privilege name keys (e.g. 'SeShutdownPrivilege') that were
      # changed by this function, and the previous enabled value as hash values (true/false).
      # E.g. {'SeShutdownPrivliege' => true} means SeShutdownPrivilege was changed from true to false. 
      def self.set_privileges(luid_attributes, privs)
        return {} unless privs.any?
        pToken = FFI::MemoryPointer.new(:ulong)
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, pToken)
        pTokenPrivs = FFI::MemoryPointer.new TOKEN_PRIVILEGES.size + LUID_AND_ATTRIBUTES.size * (privs.count - 1)
        tp = TOKEN_PRIVILEGES.new pTokenPrivs
        tp[:PrivilegeCount] = privs.count
        privs.each_with_index do |priv, i|
          luid = LUID.new
          LookupPrivilegeValue(nil, priv, luid.to_ptr)
          luid_and_attributes = LUID_AND_ATTRIBUTES.new pTokenPrivs + TOKEN_PRIVILEGES.offset_of(:Privileges) + LUID_AND_ATTRIBUTES.size * i
          luid_and_attributes[:Luid] = luid
          luid_and_attributes[:Attributes] = luid_attributes
          tp[:Privileges][0] = luid_and_attributes if i == 0
        end
        pOldTp = FFI::MemoryPointer.new pTokenPrivs.size
        returnLength = FFI::MemoryPointer.new :ulong
        AdjustTokenPrivileges(pToken.read_ulong, false, pTokenPrivs, pTokenPrivs.size, pOldTp, returnLength)
        # AdjustTokenPrivilieges may return successfully even if all privs are not assigned, but will
        # set errno. 
        if FFI.errno != 0
          raise SystemCallError.new('AdjustTokenPrivileges', FFI.errno)
        end
        parse_token_privs(pOldTp)
      end

      # Returns a hash with privilege string keys (e.g. 'SeShutdownPrivilege') and enabled status as values (true/false)
      def self.get_privileges
        pToken = FFI::MemoryPointer.new(:ulong)
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, pToken)
        pTokenPrivs = FFI::MemoryPointer.new TOKEN_PRIVILEGES.size + LUID_AND_ATTRIBUTES.size * 35 #XXX: 35?
        pReturnLength = FFI::MemoryPointer.new :ulong
        unless GetTokenInformation(pToken.read_ulong, TokenPrivileges, pTokenPrivs, pTokenPrivs.size, pReturnLength)
          raise SystemCallError.new('GetTokenInformation', FFI::errno)
        end
        parse_token_privs(pTokenPrivs)
      end

      def self.parse_token_privs(pTokenPrivs)
        tokenPrivs = TOKEN_PRIVILEGES.new(pTokenPrivs)
        privsHash = {}
        0.upto(tokenPrivs[:PrivilegeCount] - 1) do |i|
          luidAndAttrs = LUID_AND_ATTRIBUTES.new(pTokenPrivs + TOKEN_PRIVILEGES.offset_of(:Privileges) + LUID_AND_ATTRIBUTES.size * i)
          luid = luidAndAttrs[:Luid]
          name = FFI::MemoryPointer.new :uchar, 64
          cchName = FFI::MemoryPointer.new :ulong
          cchName.write_ulong(name.size)
          LookupPrivilegeName(nil, luid.to_ptr, name, cchName)
          privName = name.read_string(cchName.read_ulong)
          privsHash[privName] = luidAndAttrs[:Attributes] & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0
        end
        privsHash
      end
    end
  end
end
