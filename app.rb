require "sinatra"
require "erubis"
require "active_record"
require "rotp"

ActiveRecord::Base.establish_connection host: "127.0.0.1", user: "root", database: "2fa", adapter: "mysql2"
enable :sessions
set :erb, escape_html: true

class User < ActiveRecord::Base
  has_secure_password
  
  attr_accessible :name, :password, :password_confirmation
  validates :name, uniqueness: true, length: { minimum: 2 }
  
  after_create :generate_new_secret!
  
  def totp
    @totp ||= ROTP::TOTP.new(secret, timeout: 60)
  end
  
  def generate_new_secret!
    self.secret = rand((32**16)...(32**17-1)).to_s(32).upcase
    @totp = nil
    save!
  end
  
  def self.authenticate(params)
    if user = find_by_name(params[:name]) and user.authenticate(params[:password])
      # we need a little bit of leeway here to allow for clients with bad clocks
      acceptable = (-120..120).step(30).map { |offset| user.totp.at Time.now + offset }
      if acceptable.include? params[:code].to_i
        user
      else
        ["Invalid verification code"]
      end
    else
      ["Invalid username/password"]
    end
  end
end

before do
  @user = User.find session[:user_id] if session[:user_id]
end

get "/" do
  erb :index
end

get "/logout" do
  session.clear
  redirect "/"
end

get "/secret" do
  redirect "/" unless @user
  erb :secret
end

post "/register" do
  user = User.new params
  if user.save
    session[:user_id] = user.id
    redirect "/setup"
  else
    @register_errors = user.errors.full_messages
    erb :index
  end
end

post "/login" do
  auth = User.authenticate(params)
  if auth.is_a? User
    session[:user_id] = auth.id
    redirect "/"
  else
    @login_errors = auth
    erb :index
  end
end

post "/invalidate" do
  @user.generate_new_secret!
  redirect "/setup"
end

get "/setup" do
  erb :setup
end