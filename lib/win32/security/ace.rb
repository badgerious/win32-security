require File.join(File.dirname(__FILE__), 'windows', 'constants')
require File.join(File.dirname(__FILE__), 'windows', 'functions')
require File.join(File.dirname(__FILE__), 'windows', 'structs')

# The Win32 module serves as a namespace only.
module Win32
   
  # The Security class serves as a toplevel class namespace.
  class Security
      
    # The ACE class encapsulates an Access Control Entry, an element within
    # an Access Control List.
    class ACE
      include Windows::Security::Constants
      include Windows::Security::Structs
      include Windows::Security::Functions

      # The version of the Win32::Security::ACE class.
      VERSION = '0.1.0'

      # The ACE struct itself
      attr_reader :ace

      # A Win32::Security::GUID object that identifies the type of child
      # object that can inherit the ACE. 
      attr_accessor :object_type

      attr_accessor :inherited_object_type

      def initialize(arg)
        if arg.class == FFI::MemoryPointer
          @pAce = arg
          ace_header = ACE_HEADER.new(@pAce)
          acetype = {ACCESS_ALLOWED_ACE_TYPE => ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE_TYPE => ACCESS_DENIED_ACE}[ace_header[:AceType]]
          @ace = acetype.new(@pAce)
        elsif arg.class == Hash
          arg[:sid].class == SID or raise ArgumentError, ":sid must be of class Win32::Security::SID"
          [ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE].include?(arg[:type]) or raise ArgumentError, "Invalid type"
          arg[:flags] # inheritance, etc.
          arg[:mask] # FULL_CONTROL, etc.

          acetype = {ACCESS_ALLOWED_ACE_TYPE => ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE_TYPE => ACCESS_DENIED_ACE}[arg[:type]]

          # Need enough space for the SID. One DWORD worth is already allocated in the acetype, so exclude that. 
          acesize = acetype.size - FFI.type_size(Windows::Security::Functions.find_type(:dword)) + arg[:sid].sid.size
          @pAce = FFI::MemoryPointer.new(acesize)

          @ace = acetype.new(@pAce)

          @ace[:Header][:AceType] = arg[:type]
          @ace[:Header][:AceFlags] = arg[:flags]
          @ace[:Header][:AceSize] = acesize
          @ace[:Mask] = arg[:mask]
          pSid = FFI::Pointer.new(@pAce.address + @ace.offset_of(:SidStart))
          pSid.write_string(arg[:sid].sid, arg[:sid].sid.size)
        else
          raise ArgumentError, "Invalid parameter"
        end
      end

      # XXX: 'ace_' prefix?

      # Bit flags that indicate whether the ObjectType and
      # InheritedObjectType members are present. This value is set
      # internally based on the values passed to the ACE#object_type or
      # ACE#inherited_object_type methods, if any.
      def ace_flags
        @ace[:Header][:AceFlags]
      end

      def ace_size
        @ace[:Header][:AceSize]
      end

      # The ACE type, e.g. ACCESS_ALLOWED, ACCESS_DENIED, etc.
      def ace_type
        @ace[:Header][:AceType]
      end

      # Standard access rights, e.g. GENERIC_READ, GENERIC_WRITE, etc 
      def mask
        @ace[:Mask]
      end

      def to_s
        mod = Windows::Security::Constants
        btc = proc { |modulename, bits| mod.bits_to_constants(modulename, bits).join(' | ') }
        perms = btc.call(mod::GROUP_FILE_ACCESS_RIGHTS, mask)
        inheritance = btc.call(mod::GROUP_ACE_FLAGS, ace_flags)
        inheritance = 'No Inheritance' if inheritance == ''
        "#<ACE - #{sid.account} - #{perms} - #{inheritance}>"
      end

      def sid
        pSid = FFI::Pointer.new(@pAce.address + @ace.offset_of(:SidStart))
        SID.new(pSid.read_string(@ace[:Header][:AceSize] - @ace.class.size + FFI.type_size(Windows::Security::Functions.find_type(:dword))))
      end
    end
  end
end
