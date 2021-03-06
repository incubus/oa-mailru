require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class MailRu < OAuth2
      # @param [Rack Application] app standard middleware application argument
      # @param [String] client_id the application ID for your client
      # @param [String] client_secret the application secret
      def initialize(app, client_id = nil, client_secret = nil, options = {}, &block)
        client_options = {
          :site => 'https://connect.mail.ru/',
          :authorize_path => '/oauth/authorize',
          :access_token_path => '/oauth/token'
        }
        @private_key = options[:private_key]
        options = {
          :response_type => 'code',
          :grant_type => 'authorization_code'
        }
        super(app, :mail_ru, client_id, client_secret, client_options, options, &block)
      end

      protected

      def calculate_signature(params)
        str = params['uids'] + (params.sort.collect { |c| "#{c[0]}=#{c[1]}" }).join('') + @private_key
        Digest::MD5.hexdigest(str)
      end

      def user_hash
        request_params =  {
          'method' => 'users.getInfo',
          'app_id' => client_id,
          'session_key' => @access_token.token,
          'uids' => @access_token['x_mailru_vid']
        }
        request_params.merge!('sig' => calculate_signature(request_params))
        @user_hash ||= MultiJson.decode(client.request(:get, 'http://www.appsmail.ru/platform/api', request_params))[0]
      end

      def auth_hash
        data = user_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => data['uid'],
          'nickname' => data['nick'],
          'email' => data['email'],
          'user_info' => data
        })
      end

    end
  end
end
