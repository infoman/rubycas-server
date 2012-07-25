require 'casserver/authenticators/sql'

# Authenticates against a plain SQL table.
#
# See sql.rb for documentation
# This version differs from original in its matching_users method,
# which checks if the user has activated his account
#
class CASServer::Authenticators::SQLActivable < CASServer::Authenticators::SQL
  def actkey_column
    @options[:actkey_column] || 'act_key'
  end

  def matching_users
    user_model.find(:all,
                    :conditions => ["#{username_column} = ? AND #{password_column} = ? AND #{actkey_column} IS NULL",
                                                  @username,                 @password])
  end
end
