require 'casserver/authenticators/base'
require 'multi_json'

class CASServer::Authenticators::Ulogin < CASServer::Authenticators::Base
  def validate(credentials)
    read_standard_credentials(credentials)
    return false unless @username == 'ulogin' && /[0-9a-fA-F]{32}/.match(@password)

    $LOG.info "This seems to be an uLogin sign-in with token #{@password}"
    url = "https://ulogin.ru/token.php?token=#{@password}"
    response = Net::HTTP.get_response(URI.parse(url))
    raise 'Ulogin server fault' unless response.code == '200'

    data = MultiJson.decode(response.body)
    $LOG.info "Got uLogin server response: #{data.inspect}"
    if data['error'].present?
      $LOG.error "uLogin returned error: #{data['error']}"
      return false
    else
      return false unless data['verified_email'] == '1'
      @username = "ulogin_#{data['network']}_#{data['uid']}"
      @extra_attributes = {'external' => true}
      %w(email first_name last_name nickname profile network uid).each do |col|
        @extra_attributes[col] = data[col]
      end
      return true
    end
    return false
  end
end
