require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'structs')
require File.join(File.dirname(__FILE__), 'windows', 'functions')

# TODO: ACE ordering http://msdn.microsoft.com/en-us/library/aa379298.aspx

# The Win32 module serves as a namespace only.
module Win32

  # The Security class serves as a toplevel class namespace.
  class Security

    # The ACL class encapsulates an Access Control List.
    class ACL
      include Windows::Security::Constants
      include Windows::Security::Functions
      include Windows::Security::Structs
      extend Windows::Security::Functions

      # The version of the Win32::Security::ACL class.
      VERSION = '0.2.0'

      # The underlying ACL structure.
      attr_reader :acl

      # The revision level.
      attr_reader :revision

      # Creates and returns a new Win32::Security::ACL object. This object
      # encapsulates an ACL structure, including a binary representation of
      # the ACL itself, and the revision information.
      #
      def initialize(acl_struct = nil, opts = {})
        @revision = opts[:revision] || ACL_REVISION

        if acl_struct
          acl_struct.class == ACL_STRUCT or raise ArgumentError, "Invalid acl_struct"
        else
          acl_struct = ACL_STRUCT.new

          unless InitializeAcl(acl_struct, acl_struct.size, @revision)
            raise SystemCallError.new("InitializeAcl", FFI.errno)
          end
        end

        @acl = acl_struct
      end

      # @return [Array<Win32::Security::ACE>]
      def aces
        set_aces unless @cached_aces
        @aces
      end

      # Returns the number of ACE's in the ACL object.
      #
      def ace_count
        @acl[:AceCount]
      end

      def bytes_in_use
        set_size_info unless @cached_size_info
        @bytes_in_use
      end

      def bytes_free
        set_size_info unless @cached_size_info
        @bytes_free
      end

      # Adds an access allowed ACE to the given +sid+. The +mask+ is a
      # bitwise OR'd value of access rights.
      #
      def add_access_allowed_ace(sid, mask=0)
        # http://support.microsoft.com/kb/102102

        required_size = bytes_in_use + ACCESS_ALLOWED_ACE.size + GetLengthSid(sid.sid) - FFI.type_size(Windows::Security::Functions.find_type(:dword))
        pAcl = FFI::MemoryPointer.new required_size
        InitializeAcl(pAcl, required_size, @revision)
        newAcl = ACL_STRUCT.new(pAcl)
        aces.each do |ace|
          # Ordering rules say non inherited ACEs come first in the ACL
          if ace.ace_flags & INHERITED_ACE != 0
            next if ace.sid == sid # this ACE will be replaced by the new ace, so skip
            AddAce(newAcl.to_ptr, @revision, MAXDWORD, ace.ace.to_ptr, ace.ace_size)
          end
        end
        AddAccessAllowedAce(newAcl.to_ptr, @revision, mask, sid.sid)
        aces.each do |ace|
          if ace.ace_flags & INHERITED_ACE == 0
            AddAce(newAcl.to_ptr, @revision, MAXDWORD, ace.ace.to_ptr, ace.ace_size)
          end
        end
        @acl = newAcl
        invalidate_cached
        self
      end

      # Adds an access denied ACE to the given +sid+.
      #
      def add_access_denied_ace(sid, mask=0)
        unless AddAccessDeniedAce(@acl.to_ptr, @revision, mask, sid.sid)
          raise SystemCallError.new("AddAccessDeniedAce", FFI.errno)
        end
      end

      # Adds an ACE to the ACL object with the given +revision+ at +index+
      # or the end of the chain if no index is specified.
      #
      # Returns the index if successful.
      #--
      # This is untested and will require an actual implementation of
      # Win32::Security::Ace before it can work properly.
      #
      def add_ace(ace, index=MAXDWORD)
        unless AddAce(@acl, @revision, index, ace, ace.length)
          raise SystemCallError.new("AddAce", FFI.errno)
        end

        index
      end

      # Deletes an ACE from the ACL object at +index+, or from the end of
      # the chain if no index is specified.
      #
      # Returns the index if successful.
      #--
      # This is untested and will require an actual implementation of
      # Win32::Security::Ace before it can work properly.
      #
      def delete_ace(index=MAXDWORD)
        unless DeleteAce(@ace, index)
          raise SystemCallError.new("DeleteAce", FFI.errno)
        end

        index
      end

      # Finds and returns a pointer (address) to an ACE in the ACL at the
      # given +index+. If no index is provided, then an address to the
      # first free byte of the ACL is returned.
      #
      def find_ace(index = nil)
        pptr = FFI::MemoryPointer.new(:pointer)

        if index.nil?
          unless FindFirstFreeAce(@acl, pptr)
            raise SystemCallError.new("DeleteAce", FFI.errno)
          end
        else
          unless GetAce(@acl, index, pptr)
            raise SystemCallError.new("GetAce", FFI.errno)
          end
        end

        pptr.read_pointer.address
      end

      # Sets the revision information level, where the +revision_level+
      # can be ACL_REVISION1, ACL_REVISION2, ACL_REVISION3 or ACL_REVISION4.
      #
      # Returns the revision level if successful.
      #
      def revision=(revision_level)
        buf = FFI::MemoryPointer.new(:ulong)
        buf.write_ulong(revision_level)

        unless SetAclInformation(@acl, buf, buf.size, AclRevisionInformation)
          raise SystemCallError.new("SetAclInformation", FFI.errno)
        end

        @revision = revision_level

        revision_level
      end

      # Returns whether or not the ACL is a valid ACL.
      #
      def valid?
        IsValidAcl(@acl)
      end

      private

      def set_aces
        # TODO: revision?
        @aces = []
        ace_count.times do |n|
          pAcl = @acl.to_ptr
          ppAce = FFI::MemoryPointer.new :pointer
          ret = GetAce(pAcl, n, ppAce)
          ace_header = ACE_HEADER.new(ppAce.read_pointer)
          pAce = FFI::MemoryPointer.new ace_header[:AceSize]
          pAce.write_string(ppAce.read_pointer.read_string(ace_header[:AceSize]), ace_header[:AceSize])
          @aces << ACE.new(pAce)
          @cached_aces = true
        end
      end

      def set_size_info
        aclInformation = ACL_SIZE_INFORMATION.new
        GetAclInformation(@acl.to_ptr, aclInformation.to_ptr, aclInformation.size, AclSizeInformation)
        @bytes_in_use = aclInformation[:AclBytesInUse]
        @bytes_free = aclInformation[:AclBytesFree]
        @cached_size_info = true
      end

      # Some information is not available directly in the ACL structure and needs to be 
      # generated with some API calls. These items are lazily fetched, and cached for
      # future use. If the ACL changes, the caches are invalidated. 
      def invalidate_cached
        @cached_aces = nil
        @cached_size_info = nil
      end
    end
  end
end
