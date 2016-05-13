require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Eloqua < OmniAuth::Strategies::OAuth2

      args [:client_id, :client_secret] # ?

      option :name, "eloqua"
      option :provider_ignores_state, false

      option :client_options, {
        site: 'https://login.eloqua.com',
        authorize_url: '/auth/oauth2/authorize'
      }

      option :authorize_options, [
        :response_type,
        :client_id,
        :redirect_uri,
        :scope ] # ???

      def request_phase
        conn = Faraday.new(url: client.auth_code.authorize_url) do |faraday|
          faraday.request  :url_encoded
          faraday.response :logger
          faraday.adapter  Faraday.default_adapter
        end

        response = conn.get( '', { grant_type: "client_credentials",
                        client_secret: request.
                          env['omniauth.strategy'].
                          options[:client_secret]
        })


        # redirect callback_url
      end


      def eloqua_auth_url
        client.
          auth_code.
          authorize_url({ redirect_uri: callback_url,
                          grant_type: "client_credentials",
                          client_secret: request.
                            env['omniauth.strategy'].
                            options[:client_secret]
                         })
      end


      def callback_phase
        binding.pry
#        if request.params['error'] || request.params['error_reason']
          #raise CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
        #end
        #if !options.provider_ignores_state && (request.params['state'].to_s.empty? || request.params['state'] != session.delete('omniauth.state'))
          #raise CallbackError.new(nil, :csrf_detected)
        #end

        #hash = Hashie::Mash.new
        #hash.token = request.params['access_token']
        #hash.refresh_token = request.params['refresh_token']
        #hash.expires_in = request.params['expires_in']
        #self.access_token = hash

        #self.env['omniauth.auth'] = auth_hash
        #call_app!
      #rescue ::OAuth2::Error, CallbackError => e
        #fail!(:invalid_credentials, e)
      #rescue ::MultiJson::DecodeError => e
        #fail!(:invalid_response, e)
      #rescue ::Timeout::Error, ::Errno::ETIMEDOUT, Faraday::Error::TimeoutError => e
        #fail!(:timeout, e)
      #rescue ::SocketError, Faraday::Error::ConnectionFailed => e
        #fail!(:failed_to_connect, e)
      #end

      #credentials do
        #hash = {'token' => access_token['token']}
        #hash.merge!('refresh_token' => access_token['refresh_token'])
        #hash.merge!('expires_in' => access_token['expires_in'])
        #hash.merge!('expires' => true)
        #hash
      #end
      end

    end
  end
end

OmniAuth.config.add_camelization 'eloqua', 'Eloqua'
