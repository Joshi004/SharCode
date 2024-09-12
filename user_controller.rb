class Api::UsersController < ApplicationController
    before_action :authenticate_user!, except: [:exists, :klaviyo, :forgot, :reset, :verify_reset, :confirm, :resend_confirm, :unlock, :resend_unlock, :password_pwned, :validate_family_token, :accept, :reject]
    before_action only: [:message, :create] do
      authorize_roles(%w(admin group_manager group_support))
    end
    before_action only: [:destroy] do
      authorize_roles(%w(admin group_manager group_support end_user))
    end
    before_action only: [:index] do
      authorize_roles(%w(admin operator group_manager group_support developer))
    end
  
    def index
  
      get_by_roles(params) and return if params[:role]
  
      params[:sort] = 'updated_at' unless params[:sort]
      params[:order] = 'asc' unless params[:order]
      params[:page] = 1 unless params[:page]
      params[:per_page] = 10 unless params[:per_page]
  
      params[:sort] = 'updated_at' unless User.column_names.include?(params[:sort])
      params[:order] = 'asc' unless %w(asc desc).include?(params[:order])
  
      users = User.includes(:metadata, :allowed_advisor_regions, :operator_categories, :groups, :group_members, :user_roles => [:role])
  
      if params[:q] && !params[:q].blank?
        if params[:q].include?(":")
          query_params_arry = params[:q].scan(/([\w]+[^:]*):([\s]*[^\s]+[\s]*)/)
          user_ids = User.get_user_ids_from_field_value_search(query_params_arry) if query_params_arry.present?
          users = User.where("id in (?)", user_ids)
        else
          phones_user_ids = User.get_user_ids_for_phone_field(params[:q])
  
          users = User.where('false')
  
          params[:q].gsub! '[[PLUS_SIGN]]', '+'
          params[:q].split(/\|/).each do |q|
            users = users.or(User.where('email LIKE ?', '%' + q + '%'))
            if q.to_i != 0
              users = users.or(User.where('users.id IN (SELECT DISTINCT user_id FROM orders WHERE id=?)', q.to_i))
              users = users.or(User.where('users.id = ?', q.to_i))
            elsif !q.include?('@')
              users = users.or(User.where('users.tap_user_id is not null and  users.tap_user_id = ?', q))
              users = users.or(User.where('name LIKE ?', '%' + q + '%'))
              users = users.or(User.where('company LIKE ?', '%' + q + '%'))
              users = users.or(User.where('billing_id = ?', q))
              users = users.or(User.where('users.id IN (
                SELECT DISTINCT user_id FROM user_roles
                INNER JOIN roles ON (user_roles.role_id = roles.id)
                WHERE roles.name LIKE ? GROUP BY user_roles.id)', '%' + q + '%'))
              users = users.or(User.where('users.id IN (
                SELECT DISTINCT user_id FROM orders
                INNER JOIN plans ON (orders.plan_id = plans.id)
                WHERE plans.description LIKE ? or plans.code = ? GROUP BY orders.id)', '%' + q + '%', q.strip))
            end
          end
          users = users.or(User.where(id: phones_user_ids))
        end
      end
      if params[:migrated]
        users = users.where('old_uid is not null')
      end
      if params[:failed]
        users = users.where('users.id IN (SELECT DISTINCT user_id FROM orders WHERE state=\'expired\' and billing_failed=1)')
      end
      if params[:upcoming]
        users = users.where('users.id IN (SELECT DISTINCT user_id FROM orders WHERE state LIKE \'active\'
           AND DAYOFYEAR(created_at) BETWEEN DAYOFYEAR(NOW()) AND DAYOFYEAR(NOW() + INTERVAL 7 DAY))')
      end
      if params[:admin]
        users = users.where("users.id IN (SELECT user_id FROM user_roles u join roles r on u.role_id = r.id WHERE r.name in ('admin', 'group_manager'))")
      end
      if params[:advisors]
        users = users.where('users.id IN (SELECT user_id FROM user_roles u join roles r on u.role_id = r.id WHERE r.name != \'user\')')
      end
  
      unless current_user.admin? || current_user.group_manager? || current_user.group_support?
        if current_user.team_lead?
          users = users.where(region_id: current_user.region_id)
          users = users.where('users.id not in (select user_id from user_roles ur join roles rl on ur.role_id = rl.id and rl.name = \'admin\')')
        else
          users = users.where('users.id = ?', current_user.id)
        end
      end
  
      users = users.where('email not like ?', '%@deleted.abine.com')
      users = users.where(is_active: true) if current_user.team_lead? && !current_user.admin?
      users = users.order(Arel.sql(params[:sort]+' '+params[:order]))
      users = users.paginate(:page => params[:page], :per_page => params[:per_page])
  
      AuditLog.log(current_user.id, 'list', 'User')
  
      render_page(users, nil, {index: true})
    end
  
    def get_by_roles(params)
      roles_mapping = {
        operators_admins: %w[first_operator operator admin],
        operators: %w[first_operator operator],
        reviewers: %w[reviewer admin subsequent_reviewer],
        developers: ['developer'],
        score_team_lead: %w[score_team_lead],
        score_admins: %w[score_team_lead score_advisor admin]
      }
      users = User.includes(:metadata, :region).with_roles(roles_mapping[params[:role].to_sym]).order(Arel.sql('name ASC'))
      if params[:check_region] == "1"
        users = users.where(region_id: [current_user.region_id, Region.where(name: 'Automation').first.id])
      end
      render_success users.as_json({dropdown: true})
    end
  
    def offers
      offers = []
      orders = Order.where(user_id: current_user.id).where('state = \'active\' or state = \'canceled\' or state = \'expired\'')
      if params[:order_id]
        orders = orders.where(id: params[:order_id])
      end
      orders.each do |order|
        offers << {id: order.id, offers: order.offers(params[:where])}
      end
      render_success offers
    end
  
    def show
      if current_user.admin? || current_user.group_support? || current_user.group_manager?
        user = User.find(params[:id])
        url = UserMetadata.create_if_required(user).privacy_report_login_url
        @user = user.as_json_for_admin
        @user["privacy_report_login_url"] = url if url
      elsif current_user.team_lead?
        user = User.find(params[:id])
        if user.region_id == current_user.region_id
          @user = user.as_json_for_team_lead
        else
          @user = current_user
        end
      else
        @user = current_user
      end
  
      AuditLog.log(current_user.id, 'view', 'User', @user.is_a?(Hash) ? @user["id"] : @user.id)
  
      render_success @user
    end
  
    def create
      if User.find_by_email(params[:email])
        render_error({error: "Duplicate email id"})
        return
      end
      @user = User.new
      @user.update(admin_user_params)
  
      if !@user.errors.empty?
        render_error({error: @user.errors.full_messages[0]})
        return
      end
  
      if params[:roles]
        update_user_roles
      end
  
      UserRole.set_operator_roles(@user)
  
      if params[:categories]
        params[:categories].each do |category|
          category = Category.where(name: category).first
          if category && !OperatorCategory.exists?(user_id: @user.id, category_id: category.id)
            OperatorCategory.create({user_id: @user.id, category_id: category.id})
          end
        end
      end
  
      @user.confirm
  
      AuditLog.log(current_user.id, 'create_object', 'User', @user.id)
  
      render_success @user
    end
  
    def update
      begin
        @user = User.find(params[:id])
        old_roles = @user.roles
        old_categories = @user.categories
        old_active_flag = @user.is_active
        old_allowed_regions = @user.allowed_advisor_regions.includes(:region).pluck(:code)
        old_email = @user.email
        if old_active_flag && !params[:is_active]
          IncomingPhone.where(user_id: @user.id).first&.release_phone
        end
        if (current_user.admin? || current_user.group_support? || current_user.group_manager?) && current_user.id != params[:id].to_i
          if @user.allow_email_change
            @user.update(admin_user_params)
            @user.update_billing_email
          else
            @user.update(admin_user_params_without_email)
          end
          unless @user.errors.empty?
            render_error({error: @user.errors.full_messages[0]})
            return
          end
          # set company flag for all orders/subs/reports
          is_company = @user.company && @user.company != ''
          @user.orders.each do |order|
            order.is_company = is_company
            order.save!
            order.subscriptions.each do |sub|
              sub.is_company = is_company
              sub.save!
              sub.reports.each do |report|
                if report.is_company != is_company
                  report.is_company = is_company
                  report.save!
                end
              end
            end
          end
          return if set_theme_interface(@user)
          return if set_language(@user)
        elsif current_user.team_lead? && current_user.id != params[:id].to_i
          if current_user.region_id == @user.region_id
            @user.update(admin_user_params)
          else
            @user = nil
          end
          unless @user.errors.empty?
            render_error({ error: @user.errors.full_messages[0] })
            return
          end
        else
          @user = current_user
          return if set_theme_interface(current_user)
          return if set_tos_accepted(current_user)
  
          change_params = user_params
          unless @user.allow_email_change
            change_params = user_params_without_email
          end
          if change_params.has_key? :email
            masked_domains = Masking::Email::DisposableEmailApi.new().get_all_disposable_domains rescue nil
            email_domain = change_params[:email].split('@').pop
            if masked_domains && masked_domains.map{|domain| domain["name"]}.include?(email_domain)
              render_error({error: "This email address domain is not allowed."})
              return
            end
          end
  
          User.transaction do
            @user.update_with_password(change_params)
            if !@user.errors.empty?
  
              if @user.errors && @user.errors['current_password'] && @user.errors['current_password'][0] == 'is invalid' && !params[:password].blank?
                UserNotifyMailer.send_failed_change_password_email(@user, request.user_agent, remote_ip, Time.now.utc.strftime('%c %Z')).deliver_now
              end
  
              render_error({ error: @user.errors.full_messages[0] })
              return
            else
              @user.update_billing_email
              set_language(@user)
              if @user.email != old_email
                target_email = Masking::Email::TargetEmailApi.new(current_user).find_target_record(old_email, 1)
                if target_email.present? && target_email["id"].present?
                  response = Masking::Email::TargetEmailApi.new(current_user).update(target_email["id"].to_s, nil, @user.email)
                  if response["error"].present?
                    # return keyword inside transaction will always rollback, so here it will return back with error message
                    return render_error({ error: response["error"] }) if response["error"].present?
                  end
                end
              end
            end
          end
          unless params[:password].blank?
            UserNotifyMailer.delay(priority: -1).send_change_password_email(@user, request.user_agent, remote_ip, Time.now.utc.strftime('%c %Z'))
          end
        end
        if @user
          if @user.tap_user_id.present? || @user.company.present? && params[:portability_email]
            @user.portability_email = params[:portability_email]
            @user.save!
          end
          metadata = UserMetadata.create_if_required(@user)
          if params[:has_2fa]
            if params[:type] == 'app'
              # app 2fa
              @user.lock_2fa = params[:lock_2fa]
              @user.save!
              if !@user.has_app_2fa
                if @user.otp_secret_key && @user.otp_secret_key.starts_with?('provisional-')
                  @user.otp_secret_key.slice! 'provisional-'
                  if params.key?(:confirm_first_time_otp) && !params[:confirm_first_time_otp].blank?
                    if @user.authenticate_otp(params[:confirm_first_time_otp].gsub(/[^0-9]+/, ''))
                      @user.activate_2fa @user.otp_secret_key
                    else
                      return render_error({error: "Invalid OTP given"})
                    end
                  else
                    return render_error({error: "No first-time OTP given"})
                  end
                else
                  return render_error({error: "Invalid request.  Please reload page and retry."})
                end
              end
            elsif params[:type] == 'email'
              # email 2fa
              if @user.has_app_2fa
                @user.deactivate_2fa
              end
              metadata.trust_all_devices = false
              metadata.save
              @user.lock_2fa = false
              @user.save!
            end
          else
            if @user.has_app_2fa
              @user.deactivate_2fa
            end
            if @user.has_email_2fa
              @user.deactivate_email_2fa
            end
          end
        end
      rescue ActiveRecord::RecordNotUnique
        render_error({error: 'Email id already used'})
        return
      end
  
      begin
        if current_user.admin? || current_user.group_support? || current_user.group_manager?
          priority = !params[:priority].blank?
          @user.priority = priority
          @user.save!
          # update priority of future pending reports of this user
          subscription_ids =  Subscription.where("user_id = ?", @user.id).pluck(:id)
          if priority
            Report.where("status = ? and subscription_id in (?)",'pending',subscription_ids).update(priority: 1)
          else
            Report.where("status = ? and subscription_id in (?)",'pending',subscription_ids).update(priority: 0)
          end
        end
      rescue ActiveRecord::RecordInvalid => e
        render_error({error: e.message})
        return
      end
  
      if current_user.admin? || current_user.group_support? || current_user.group_manager?
  
        if params[:roles]
          update_user_roles
        end
  
        if params[:categories]
          @user.operator_categories.each do |operator_category|
            unless params[:categories].include?(operator_category.category_name)
              operator_category.destroy
            end
          end
          params[:categories].each do |category|
            category = Category.where(name: category).first
            if category && !OperatorCategory.exists?(user_id: @user.id, category_id: category.id)
              OperatorCategory.create({user_id: @user.id, category_id: category.id})
            end
          end
        end
  
        if params[:allowed_regions]
          @user.allowed_advisor_regions.each do |allowed_region|
            unless params[:allowed_regions].include?(allowed_region.region.code)
              allowed_region.destroy
            end
          end
          params[:allowed_regions].each do |region|
            region = Region.where(code: region).first
            if region && !AllowedAdvisorRegion.exists?(user_id: @user.id, region_id: region.id)
              AllowedAdvisorRegion.create({user_id: @user.id, region_id: region.id})
            end
          end
        end
      end
  
      if params[:categories] || params[:roles] || params[:is_active] || params[:allowed_regions] || params[:password]
        @user.reload
        @user = User.find(@user.id)
        roles = @user.roles
        categories = @user.categories
        allowed_regions = @user.allowed_advisor_regions.includes(:region).pluck(:code)
        is_active = @user.is_active
        new_roles = roles - old_roles
        removed_roles = old_roles - roles
        new_categories = categories - old_categories
        removed_regions = old_allowed_regions - allowed_regions
        new_regions =  allowed_regions - old_allowed_regions
        removed_categories = old_categories - categories
        comment = []
        comment << "Roles added: #{new_roles.join(', ')}" unless new_roles.empty?
        comment << "Roles removed: #{removed_roles.join(', ')}" unless removed_roles.empty?
        comment << "Categories added: #{new_categories.join(', ')}" unless new_categories.empty?
        comment << "Categories removed: #{removed_categories.join(', ')}" unless removed_categories.empty?
        comment << "Allowed Regions removed: #{removed_regions.join(', ')}" unless removed_regions.empty?
        comment << "Allowed Regions added: #{new_regions.join(', ')}" unless new_regions.empty?
        comment << "User active flag changed: #{old_active_flag} -> #{is_active}" if is_active != old_active_flag
        comment << "Password changed" if params[:password] and (current_user.admin? || current_user.team_lead?)
        @user.comments.create({comment: comment.join("\n")+"\t", user_id: current_user.id}) unless comment.empty?
      end
      AuditLog.log(current_user.id, 'update_object', 'User', params[:id])
  
      render_success @user
    end
  
    def get_qr
      if (current_user.admin? || current_user.group_support? || current_user.group_manager?) || current_user.id == params[:id].to_i
        @user = User.find(params[:id])
        if !@user.has_app_2fa
          provisional = true
          secret = ROTP::Base32.random
          qr = RQRCode::QRCode.new('otpauth://totp/deleteme?secret=' + secret, :size => 7, :level => :h )
          @user.otp_secret_key = 'provisional-' + secret
          @user.save!
        else
          return render_error ({error: "User already has 2FA activated, ask an admin to reset your 2FA if needed."})
        end
        render_success({secret: secret, provisional: provisional, qr: qr.as_png().resize(200, 200).to_data_url })
      end
    end
  
    def clear_cache
      if current_user.admin? || current_user.team_lead?
        @user = User.find(params[:id])
        ip_address = IntrusionDetection::Cache.get(@user.email.downcase)
        IntrusionDetection::Cache.clear(ip_address) if ip_address
        IntrusionDetection::Cache.clear(@user.current_sign_in_ip) if @user.current_sign_in_ip
        IntrusionDetection::Cache.clear(@user.last_sign_in_ip) if @user.last_sign_in_ip
  
        render_success({status: "success"})
      else
        render_error({status: "invalid request"})
      end
    end
  
    def whitelist_user
      if current_user.admin?
        @user = User.find(params[:id])
  
        known_device = KnownDevice.find_by(user_id: @user.id, device_id: params[:device_id])
        if known_device
          ip_address = IntrusionDetection::Cache.get(@user.email.downcase)
          IntrusionDetection::Cache.clear(ip_address) if ip_address
          IntrusionDetection::Cache.clear(params[:ip_address])
  
          known_device.approved = true
          known_device.country = UserNotifyMailer.new.country_from_ip(params[:ip_address])
          known_device.save
          render_success({status: "success"})
        else
          render_error({status: "Could not find device to mark as whitelisted"})
        end
      else
        render_error({status: "Invalid request"})
      end
    end
  
    def unlock_account_by_admin
      if current_user.admin?
        @user = User.find(params[:id])
        @user.unlock_access!
        render_success({ status: "success" })
      else
        render_error({ status: "invalid request" })
      end
    end
  
    def exists
      user = User.where(email: params[:email]).first
      response = {status: user.blank? ? 'ok' : 'duplicate'}
      if user && current_user && (current_user.admin? || current_user.group_support? || current_user.group_manager?)
        response[:groups] = GroupMember.includes(:group).where(user_id: user.id).pluck(:name, :role)
        if params[:billing] == 'yes'
          if user.billing_id
            begin
              billing_account = user.billing_account.as_json
              if billing_account['account']['sources']['data'][0]
                response[:billing] = billing_account['account']['sources']['data'][0]
              end
            rescue
            end
          end
          response[:billing] = {} unless response[:billing]
          if user.billing_address
            response[:billing][:address] = user.billing_address.as_json
          end
        end
      end
      render_success(response)
    end
  
    def password_pwned
      response = {status: (Pwned::Password.new(params[:password]).pwned? || params[:password] =~ User::password_blacklist_regex) ? 'pwned' : 'ok'}
      render_success(response)
    end
  
    def klaviyo
      if !params[:email].blank? && params[:email] =~ /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i
        KlaviyoApi.add_to_list(params[:email])
      end
      head :ok
    end
  
    def forgot
      user = User.where(email: params[:email]).first
      if user
        if user.allow_password_change
          user.send_reset_password_instructions
        else
          render_error('Password change disabled for your account.  Please contact your admin.')
          return
        end
      end
      render_success({status: 'ok'})
    end
  
    def confirm
      user = User.confirm_by_token(params[:token])
      unless user.id
        render_error({error: user.errors.full_messages[0]})
      else
        render_success({status: 'ok'})
      end
    end
  
    def resend_confirm
      user = User.where(email: params[:email]).first
      if !user
        render_error({error: 'Invalid request'})
      else
        Mails::AutomatedEmailHarness.send_mail(user, 'ResendActivation')
        render_success({status: 'ok'})
      end
    end
  
    def unlock
      user = User.unlock_access_by_token(params[:token])
      unless user.id
        render_error({error: user.errors.full_messages[0]})
      else
        user.confirm # as they also verified their email
        render_success({status: 'ok'})
      end
    end
  
    def resend_unlock
      user = User.where(email: params[:email]).first
      if !user
        render_error({error: 'Invalid request'})
      else
        user.resend_unlock_instructions
        render_success({status: 'ok'})
      end
    end
  
    def verify_reset
      user = User.with_reset_password_token(params[:token])
      if user
        if user.allow_password_change
          render_success({status: 'ok', has_app_2fa: user.has_app_2fa, lock_2fa: user.lock_2fa})
        else
          render_error({error: 'Password reset disabled for your account.  Please contact your admin.'})
        end
      else
        render_error({error: 'Password reset token expired or invalid.'})
      end
    end
  
    def reset
      user = User.reset_password_by_token(params)
      unless user.id
        render_error({error: 'Password reset token expired or invalid.'})
      else
        if user.errors.empty?
          UserNotifyMailer.delay(priority: -1).send_change_password_email(user, request.user_agent, remote_ip, Time.now.utc.strftime('%c %Z'))
          if user.has_app_2fa
            # reset password should deactivate 2fa
            if !user.lock_2fa
              user.deactivate_2fa
            end
          end
          if user.has_email_2fa
            user.deactivate_email_2fa
          end
          user.unlock_access!
          user.confirm # as they also verified their email
          render_success({status: 'ok'})
        else
          render_error({error: user.errors.full_messages[0]})
        end
      end
    end
  
    def autologin
      token = nil
      if current_user.admin? || current_user.group_support? || current_user.group_manager?
        user = User.find(params[:id])
        if user
          token = user.get_auto_login_token(true, false, current_user.id)
        end
      end
      AuditLog.log_action(current_user, 'auto_login', "generated url #{user.id}")
      return render_success({token: token})
    end
  
    def destroy
      return user_not_authorized if current_user.is_login_via_admin_token?
      if current_user.admin? || current_user.group_support? || current_user.group_manager?
        user = User.find(params[:id])
        if user && !(user.admin? || user.group_support? || user.group_manager?) && !user.operator?
          user.clean_delete
          user.comments.create({comment: "Deleted the user \t", user_id: current_user.id})
        end
      elsif current_user.end_user? && current_user.id == params[:id].to_i
        current_user.delay(run_at: 5.minutes.from_now).clean_delete
      end
      AuditLog.log(current_user.id, 'remove', 'User', params[:id])
      return render_success({})
    end
  
    def mobile_register
      if params[:device_id]
        device = UserMobileDevice.where(user_id: current_user.id, device_id: params[:guid]).first_or_create
      else
        device = UserMobileDevice.where(user_id: current_user.id, device_token: params[:token]).first_or_create
      end
      device.device_token = params[:token]
      device.device_id = params[:guid]
      device.device_type = params[:type]
      device.save!
      render_success(device.as_json)
    end
  
    def mobile_unregister
      if params[:device_id]
        device = UserMobileDevice.where(user_id: current_user.id, device_id: params[:guid]).first
      else
        device = UserMobileDevice.where(user_id: current_user.id, device_token: params[:token]).first
      end
      if device
        device.delete!
      end
      render_success({})
    end
  
    def message
      user = User.find(params[:id])
      response = nil
      if user
        status = 'No mobile device registered for this user'
        devices = UserMobileDevice.where(user_id: user.id).pluck(:device_token)
        if devices.length > 0
          if ENV['FCM_SERVER_KEY']
            require 'fcm'
            fcm = FCM.new(ENV['FCM_SERVER_KEY'])
            options = {notification: JSON.parse(params[:message]), content_available: true}
            response = fcm.send(devices, options)
            status = 'Message sent to '+devices.length.to_s+' mobile devices.'
          else
            status = 'FCM_SERVER_KEY environment variable not set'
          end
        end
      else
        status = 'Invalid user id'
      end
      render_success({status: status, response: response})
    end
  
    def mark_portability_email
      if !(current_user.end_user? && !current_user.is_login_via_admin_token?)
        render_error({error: 'User not authorized.'})
        return
      end
  
      unless params[:email]
        render_error({error: 'Invalid parameters.'})
        return
      end
      if params[:user_id] == current_user.id
        user = current_user
      else
        user = User.find(params[:user_id])
        is_account_manager = SeatDelegation.where(delegatee_id: current_user.id, delegator_id: user.id).exists?
        unless is_account_manager
          render_error({error: 'User not authorized.'})
          return
        end
      end
      if user
        user.portability_email = params[:email]
        user.save
        render_success({ portability_email: user.portability_email })
      else
        render_error({error: 'Error updating portability email.'})
      end
    end
  
    def validate_family_token
      if params[:token].blank?
        render_error({error: 'No token passed.'})
        return
      end
      begin
        family_member, relative, token = fetch_details_from_token(params[:token])
        if family_member.present? && family_member.status == 'accepted'
          render_error({error: 'Invalid token/link.'})
          return
        end
      rescue ActiveRecord::RecordNotFound => e
        render_error({error: 'Invalid token/link.'})
        return
      end
      token_parts = params[:token].split(':')
      if token != token_parts[4]
        render_error({error: 'Invalid token/link.'})
        return
      end
      render_success family_member
    end
  
    def accept
      if params[:token].blank?
        render_error({error: 'No token passed.'})
        return
      end
      family_member, user, token = fetch_details_from_token(params[:token])
      token_parts = params[:token].split(':')
      if token != token_parts[4]
        render_error({error: 'Invalid token/link.'})
        return
      end
      if family_member.status != 'invited' && family_member.status != 'accepted'
        render_error({error: 'Link already used.'})
        return
      end
  
      if user
        # existing user without password
        if !user.has_password && params[:password].blank?
          render_error({error: 'password is required.'})
          return
        end
  
        if !user.has_password && params[:password].present?
          user.update({password: params[:password]})
          user.has_password = true
          user.save
          if !user.errors.empty?
            render_error({error: user.errors.full_messages[0]})
            return
          end
        elsif user.has_password && params[:password].present?
          valid_password = user.valid_password?(params[:password])
          unless valid_password
            render_error({error: "login failed invalid password."})
            return
          end
        end
        # mark user as confirmed
        user.confirm
  
        family_member.accepted
  
        # accept any subscription
        subscription = Subscription.find(family_member.subscription_id)
        parent_user_id = subscription.user_id
        if subscription && family_member.status == 'accepted'
          subscription.user_id = family_member.relative_id
          subscription.save!
          order = subscription.order
          if order && order.order_type != 'family_managed'
            order.order_type = 'family_managed'
            order.save!
          end
        end
  
        mail = MailScheduled.where(user_id: parent_user_id, mail_type: 'NoDatasheetAfter3Days')
                            .where('params like concat(\'%order_id":\', ?, \'%\')', order.id)
                            .where('params like concat(\'%subscription_id":\', ?, \'%\')', subscription.id).first
        if mail.present?
          mail.destroy if !mail.ran
          Mails::AutomatedEmailHarness.delay.schedule_mail(user.id, 'NoDatasheetAfter3Days', DateTime.now + 3.days, {order_id: order.id, subscription_id: subscription.id, datasheet_id: subscription.data_sheet.id})
        end
        @resource = user
        @token = @resource.create_custom_token(request)
        @resource.save
  
        sign_in(:user, @resource, store: false, bypass: false)
        @resource.set_user_context_cookie(@token.client, cookies)
  
        # unmark deletion
        @resource.pre_delete_notified = nil
        @resource.save
  
        AuditLog.log(current_user.id, 'accept', 'FamilyMember', family_member.id)
  
        render json: {
          data: @resource.as_json(except: [
            :tokens, :created_at, :updated_at
          ]),
        }
        return
      end
    end
  
    def reject
      if params[:token].blank?
        render_error({error: 'No token passed.'})
        return
      end
      family_member, relative, token = fetch_details_from_token(params[:token])
      token_parts = params[:token].split(':')
      if token != token_parts[4]
        render_error({error: 'Invalid token/link.'})
        return
      end
  
      if family_member.status != 'invited'
        if family_member.status == 'rejected'
          render_error({ error: 'Link already used.' })
        else
          render_error({ error: 'Invalid token/link.' })
        end
        return
      end
  
      family_member.rejected
  
      if family_member.status == 'rejected'
        Mails::AutomatedEmailHarness.send_mail(family_member.user, 'FamilyMemberInviteRejection', {member_id: family_member.id})
      end
  
      render_success({status: 'ok'})
  
    end
  
    def admin_user_params
      params.permit(:password, :password_confirmation, :email, :name, :company, :is_active, :region_id, :allow_password_change, :allow_email_change)
    end
  
    def admin_user_params_without_email
      params.permit(:password, :password_confirmation, :name, :company, :is_active, :region_id, :allow_password_change, :allow_email_change)
    end
  
    def user_params
      params.permit(:password, :password_confirmation, :email, :name, :company, :current_password, :send_privacy_letter, :send_promotions)
    end
  
    def user_params_without_email
      params.permit(:password, :password_confirmation, :name, :company, :current_password, :send_privacy_letter, :send_promotions)
    end
  
    def user
      @user ||= User.find(params[:id])
    end
  
    def set_theme_interface(user)
      if user && ((%w[v1 v2].include? params[:ui_version]) || (%w[dark-theme light-theme].include?params[:theme]))
        metadata = UserMetadata.create_if_required(user)
        metadata.ui_version = params[:ui_version] if params[:ui_version]
        metadata.theme = params[:theme] if params[:theme]
        metadata.save
        AuditLog.log(current_user.id, 'update_object', 'User', params[:id])
        render_success(user)
        true
      end
    end
  
    def set_tos_accepted(user)
      if user && params[:tos_accepted]
        user.tos_accepted = true
        user.save
        AuditLog.log(current_user.id, 'update_object', 'User', params[:id])
        render_success(user)
        true
      end
    end
  
    def set_language(user)
      AuditLog.log(current_user.id, 'update_object', 'User', params[:id])
      if user && ((%w[en de].include? params[:language])) && user.language != params[:language]
        metadata = UserMetadata.create_if_required(user)
        metadata.language = params[:language]
        metadata.save
        unless current_user.roles.include?('user')
          if metadata.language == 'de'
            user.comments.create({ comment: "Language changed - German\t", user_id: current_user.id })
          else
            user.comments.create({ comment: "Language changed - English\t", user_id: current_user.id })
          end
        end
      end
    end
  
    def check_datasheet_email_exists
      found = false
      begin
        datasheets = DataSheet.where("subscription_id in (select id from subscriptions where user_id = ?)", current_user.id)
        datasheets.each do |ds|
          ds_emails = ([ds.email&.email&.downcase] + ds.alternate_emails.map(&:email).map(&:downcase)).uniq
          if ds_emails.include?(params[:email].downcase)
            found = true
            break
          end
        end
        render_success found
      rescue => e
        render_error ({error: e.message})
      end
    end
  
    protected
  
    def update_user_roles
      @user.user_roles.each do |user_role|
        unless params[:roles].include?(user_role.role.name)
          user_role.destroy
        end
      end
      params[:roles].each do |role|
        role = Role.where(name: role).first
        if role && !UserRole.exists?(user_id: @user.id, role_id: role.id)
          UserRole.create({ user_id: @user.id, role_id: role.id })
          if role.name == 'admin'
            user_details = {user_id: self.user.id, user_name: @user.name, user_email: @user.email, done_by_name: current_user.name}
            AdminUserNotifyMailer.admin_user_creation_email(user_details).deliver unless Rails.env.development?
          end
        end
      end
  
      UserRole.set_operator_roles(@user)
    end
  
    def fetch_details_from_token(token)
      token_parts = token.split(':')
      family_member_id = token_parts[1]
      relative_id = token_parts[2]
      member = FamilyMember.find(family_member_id)
      relative = member.relative
      token = member.get_token_hash(token_parts[0], token_parts[3])
      [member, relative, token]
    end
  end
  