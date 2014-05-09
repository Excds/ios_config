require 'cfpropertylist'
require 'plist'

module IOSConfig
  class Profile
    require 'openssl'

    attr_accessor :allow_removal, # if profile can be deleted by device user. defaults to true
                  :description,   # (optional) displayed in device settings
                  :display_name,  # displayed in device settings
                  :identifier,
                  :organization,  # (optional) displayed in device settings
                  :type,          # (optional) default is 'Configuration'
                  :uuid,
                  :version,       # (optional) defaults to '1'
                  :payloads,      # (optional) payloads to be contained in the profile. should be an array if type is 'Configuration'
                  :client_certs   # (optional) certificates used to encypt payloads

    def initialize(options = {})
      options.each { |k,v| self.send("#{k}=", v) }

      @allow_removal  = true if @allow_removal.nil?
      @type           ||= 'Configuration'
      @version        ||= 1
      @payloads       ||= []
    end

    # Returns a signed profile. Accepts paths as well as certs in variables when signing the profile
    def signed(mdm_cert, mdm_intermediate_cert, mdm_private_key, is_file = true)
      certificate   = OpenSSL::X509::Certificate.new(is_file ? File.read(mdm_cert) : mdm_cert)
      intermediate  = OpenSSL::X509::Certificate.new(is_file ? File.read(mdm_intermediate_cert) : mdm_intermediate_cert)
      private_key   = OpenSSL::PKey::RSA.new(is_file ? File.read(mdm_private_key) : mdm_private_key)

      signed_profile = OpenSSL::PKCS7.sign(certificate, private_key, unsigned, [intermediate], OpenSSL::PKCS7::BINARY)
      signed_profile.to_der
    end

    def unsigned(format = :binary)
      raise_if_blank [:version, :uuid, :type, :identifier, :display_name]

      profile = {
        'PayloadDisplayName'        => @display_name,
        'PayloadVersion'            => @version,
        'PayloadUUID'               => @uuid,
        'PayloadIdentifier'         => @identifier,
        'PayloadType'               => @type,
        'PayloadRemovalDisallowed'  => !@allow_removal
      }
      profile['PayloadOrganization']  = @organization if @organization
      profile['PayloadDescription']   = @description  if @description

      if @client_certs.nil?
        profile['PayloadContent'] = @payloads
      else
        encrypted_payload_content = OpenSSL::PKCS7.encrypt( @client_certs,
                                                            @payloads.to_plist,
                                                            OpenSSL::Cipher::Cipher::new("des-ede3-cbc"),
                                                            OpenSSL::PKCS7::BINARY)

        profile['EncryptedPayloadContent'] = StringIO.new encrypted_payload_content.to_der
      end

      case format
      when :binary
        profile.to_plist
      when :xml
        Plist::Emit.dump(profile)
      else
        raise ArgumentError, 'unknown format'
      end

    end

    private

    def raise_if_blank(required_attributes)
      required_attributes.each { |a| raise "#{a} must be set" if self.send(a).nil?  }
    end
  end
end
