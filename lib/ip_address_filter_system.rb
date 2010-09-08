module IpAddressFilterSystem
  extend self

    
  def self.included(klass)
    klass.send :class_inheritable_array, :ip_address_filters        
    klass.send :include, IpAddressSecurityInstanceMethods
    klass.send :extend, IpAddressSecurityClassMethods   
    
  end
  
  # instance methods 
  module IpAddressSecurityInstanceMethods
    protected 
    
    # check ip address
    def check_ip_address
      return access_denied unless self.class.check_ip_address_for(request, params, binding)
    end
    
    def access_denied
      render_optional_error_file(401)      
    end
  end
  
  # class methods
  module IpAddressSecurityClassMethods
     
    # calculates the long value of an ip address
    def ip2long(ip)
      long_value = 0
      parts = ip.split(/\./)
      while !parts.empty?
        long_value = long_value * 256 + parts.shift.to_i
      end
      long_value
    end
    
    DEFAULT_MASK = 4294967295 # ip2long("255.255.255.255")
    DEFAULT_ALLOW_LOCALHOST = false
    LOCALHOST_IP = 2130706433 # ip2long("127.0.0.1")

    
    # add the filter
    # default mask = "255.255.255.255" 
    def filter_ip_addresses(ip_addresses, options = {})
      options.assert_valid_keys(:if, :unless,
        :for, :only, 
        :for_all_except, :except,
        :mask, :allow_localhost)
      
      # only declare that before filter once
      unless (@before_filter_declared||=false)
        @before_filter_declared=true
        before_filter :check_ip_address
      end
      
      options[:only] ||= options[:for] if options[:for]
      options[:except] ||= options[:for_all_except] if options[:for_all_except]
      
      # convert any actions into symbols
      for key in [:only, :except]
        if options.has_key?(key)
          options[key] = [options[key]] unless Array === options[key]
          options[key] = options[key].compact.collect{|v| v.to_sym}
        end 
      end
                  
      self.ip_address_filters||=[]
      ip_addresses = [ip_addresses] unless Array === ip_addresses
      ip_address_filters << {:ip_addresses => ip_addresses.map{|a| self.ip2long(a)}, :options => options }
    end
    
    # check ip address for a request
    def check_ip_address_for(request, params = {}, binding = self.binding)
      return true unless Array === self.ip_address_filters
      
      
      remote_ip_address_long = ip2long(request.remote_ip)      
            
      self.ip_address_filters.each do |filter|
        ip_addresses = filter[:ip_addresses]
        options = filter[:options]
        # do the options match the params?
        
        # check the action
        if options.has_key?(:only)
          next unless options[:only].include?( (params[:action]||"index").to_sym )
        end
        
        if options.has_key?(:except)
          next if options[:except].include?( (params[:action]||"index").to_sym)
        end
        
        if options.has_key?(:if)
          # execute the proc.  if the procedure returns false, we don't need to authenticate these roles
          next unless ( String===options[:if] ? eval(options[:if], binding) : options[:if].call(params) )
        end
        
        if options.has_key?(:unless)
          # execute the proc.  if the procedure returns true, we don't need to authenticate these roles
          next if ( String===options[:unless] ? eval(options[:unless], binding) : options[:unless].call(params) )
        end
        
        # check to see if they have one of the required roles
        
        
        mask = !options[:mask].nil? ? ip2long(options[:mask]) : DEFAULT_MASK
        allow_localhost = options[:allow_localhost] || DEFAULT_ALLOW_LOCALHOST
 
        # do check for localhost
        passed = allow_localhost && remote_ip_address_long == LOCALHOST_IP
        
        # else for other ip addresses
        if !passed
          ip_addresses.each do |ip_address|            
            passed = ((remote_ip_address_long ^ ip_address) & mask) == 0            
            
            break if passed 
          end
        end
        
        # return false if the ip adress does not pass this filter
        return false unless passed
      end
      
      # all filters are being passed
      return true
    end
    
  end
end
