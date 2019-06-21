require 'omniauth-oauth2'
require 'json'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      option :name, 'line'
      option :scope, 'profile openid'

      option :client_options, {
        site: 'https://access.line.me',
        authorize_url: '/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token'
      }

      # host changed
      def callback_phase
        options[:client_options][:site] = 'https://api.line.me'
        super
      end

      def query_string
        return super if OmniAuth::OAuth2::VERSION < "1.4.0"
        # Filter out 'code', 'state' and 'friend_status_changed' param to avoid redirect_url mismatch error with omniauth-oauth2 >= 1.4.0
        return '' if request.params.keys.reject{|key| %w(code state friendship_status_changed).member?(key.to_s)}.empty?
        "?" + request.query_string.gsub(/\b&?(code|state|friendship_status_changed)=[^;&]*/, '')
      end

      uid { raw_info['userId'] }

      info do
        {
          name:        raw_info['displayName'],
          image:       raw_info['pictureUrl'],
          description: raw_info['statusMessage']
        }
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= JSON.load(access_token.get('v2/profile').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

    end
  end
end
