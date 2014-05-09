module IOSConfig
  module Payload
    class Certificate < Base

      attr_accessor :type,           # pkcs12, caroot
                    :filename,       # Certificate filename
                    :cert_path,      # Certificate file path
                    :cert_data,      # Certificate data when initialized with a variable
                    :description,    # Certificate description
                    :displayname,    #
                    :identifier,     # Certificate identifier
                    :organization,   # Certificate organization
                    :password,       # Password to unlock certificate
                    :payload_version # Payload version

      def initialize(attributes = {})
        attributes ||= {}
        required_attributes = [ :type,
          :filename,
          :description,
          :displayname,
          :identifier,
          :organization ]

          required_attributes << (attributes.has_key?(:cert_data) ? :cert_data : :cert_path)

          required_attributes.each do |attribute|
            raise ArgumentError, "#{attribute} must be specified" unless attributes[attribute]
          end

        super(attributes)
      end

      private

      def payload
        p = { 'PayloadCertificateFileName' => @filename,
              'PayloadContent' => read_cert(@cert_path, @password),
              'PayloadDescription' => @description,
              'PayloadDisplayName' => @displayname,
              'PayloadIdentifier' => @identifier,
              'PayloadOrganization' => @organization,
            }

        p['Password'] = @password unless @password.blank?

        p
      end

      def read_cert(cert_path, password = nil)
        # When initialized with a variable, ignore reading from file path.
        data = defined?(@cert_data).nil? ? File.read(cert_path) : @cert_data

        # This will throw an exception if we have an incorrect password
        if !password.nil?
          OpenSSL::PKCS12.new(data, password)
        end

        StringIO.new data
      end

      def payload_type
        case @type
        when 'pkcs12'
          'com.apple.security.pkcs12'
        when 'caroot'
          'com.apple.security.root'
        else
          raise NotImplementedError
        end
      end

      def payload_version
        @payload_version || super
      end
    end
  end
end
