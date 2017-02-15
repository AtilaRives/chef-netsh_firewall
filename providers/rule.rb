#
# Cookbook Name:: netsh_firewall
# Provider:: rule
#
# Copyright 2015 Biola University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ENABLED 			= 'enabled'
YES 				= 'oui'
NO					= 'non'
PROFILES 			= 'profiles'
V_STRIP 			= 'Domain,Private,Public'
GROUPING 			= 'groupement'
RULE_SOURCE 		= 'source de la régle'
LOCAL_SETTING		= 'local setting'

# Firewall rule creation actions
action :allow do
  new_resource.updated_by_last_action(true) if manage_rule
end

action :block do
  new_resource.updated_by_last_action(true) if manage_rule
end

# Disable a system firewall rule
action :disable do
  rule = parse_rule_output
  if rule[ENABLED] == YES
    execute "netsh advfirewall firewall set rule name=\"#{new_resource.name}\" new enable=no"
    new_resource.updated_by_last_action(true)
  end
end

# Enable a system firewall rule
action :enable do
  rule = parse_rule_output
  if rule[ENABLED] == NO
    execute "netsh advfirewall firewall set rule name=\"#{new_resource.name}\" new enable=yes"
    new_resource.updated_by_last_action(true)
  end
end

# Add a new firewall rule
def add_rule
#puts"\n in add_rule \n"
  cmd = 'netsh advfirewall firewall add rule '
  rule_args.each do |k, v|
    cmd += "#{k}=#{v} "
  end
  execute cmd
  true
end

# Convert IP addresses to CIDR notation to match netsh output
def cidr(ip_list)
#puts"\n in cidr \n"
  return ip_list if ip_list == 'any'
  ips = []
  ip_list.split(',').each do |ip|
    ips << (ip.include?('/') ? ip.strip : ip.strip + '/32')
  end
  ips.join(',')
end

# Map netsh output to resource property names
def cmd_map(k)
#puts"\n in cmd_map \n"
  {
    'direction' => 'dir',
    'profiles' => 'profile',
    'rule name' => 'name'
  }[k] || k
end

# Create or replace a rule if needed
# Return false if the resource is up to date
def manage_rule
#puts"\n in manage_rule "
  if rule_exists?
#puts" >>>>>> rule exist \n"	
    if rule_needs_update? && !system_rule?
      execute "netsh advfirewall firewall delete rule name=\"#{new_resource.name}\""
      add_rule
    else
      false
    end
  else
#puts" >>> rule don't exist \n"	
    add_rule
  end
end

# Parse netsh output for a rule
# Return a hash with keys and values in lowercase
def parse_rule_output
#puts"\n in parse_rule_output \n"
  if rule_exists?
#puts" >>>>>> rule exist \n"	
    rule = {}
    cmd = Mixlib::ShellOut.new("netsh advfirewall firewall show rule name=\"#{new_resource.name}\" verbose")
    cmd.run_command
    cmd.stdout.lines("\r\n") do |line|
      next if line.empty? || line =~ /^Ok/ || line =~ /^-/
      k, v = line.split(': ')
      v = 'any' if k == PROFILES && v.strip == V_STRIP
			k = 'name' 		if k.match 	/Nom de la/i
			k = 'localport' if k.match 	/localport/i
			k = 'activé' 	if k.match 	/activ/i
			k = 'groupement' if k.match /groupem/i
			k = 'localip' 	if k.match 	/localip/i
			k = 'remotip' 	if k.match 	/remotip/i
			k = 'protocole' if k.match	/protoco/i
			k = 'action' 	if k.match 	/action/i
			k = 'security' 	if k.match 	/security/i
			k = 'source de la régle' if k.match /source de la/i
			k = 'service' 	if k.match 	/servi/i
			k = 'description' if k.match /descriptio/i
			k = 'program' 	if k.match 	/program/i
			k =	'remoteport' if k.match /remoteport/i
			k =	'direction' if k.match 	/direction/i
			k = 'interfacetypes' if k.match /interfacetypes/i
      rule[cmd_map(k.downcase.chomp)] = v.strip.downcase unless v.nil?
    end
#puts "\n\n-----------------\n Map rule \n-----------------\n"
#p rule
    rule
	else
    fail "Firewall rule '#{new_resource.name}' not found."
  end
end

# Create a hash of resource properties
# Format the parameters for netsh
def rule_args
#puts"\n in rule_args \n"
  args = {}
  args['name'] = "\"#{new_resource.name}\""
  args['description'] = "\"#{new_resource.description}\"" if new_resource.description
  args['dir'] = new_resource.dir.to_s
  args['localip'] = cidr(new_resource.localip)
  args['localport'] = new_resource.localport unless new_resource.protocol.to_s.include? 'icmp'
  args['remoteip'] = cidr(new_resource.remoteip)
  args['remoteport'] = new_resource.remoteport unless new_resource.protocol.to_s.include? 'icmp'
  args['protocol'] = new_resource.protocol.to_s
  args['profile'] = new_resource.profile.to_s
  args['program'] = "\"#{new_resource.program}\"" if new_resource.program
  # There can only be one action
  if new_resource.action.is_a? Array
    args['action'] = new_resource.action.first.to_s
  elsif new_resource.action.is_a? Symbol
    args['action'] = new_resource.action.to_s
  end
  args
end

# Determine if a rule exists
def rule_exists?
#puts"\n in rule_exists \n"
  cmd = Mixlib::ShellOut.new("netsh advfirewall firewall show rule name=\"#{new_resource.name}\"")
  cmd.run_command
#puts cmd.stdout
  !cmd.stdout.match /Aucune/i
end

# Determine if a rule needs to be updated
# Compare the existing rule parameters with the new resource parameters
def rule_needs_update?
#puts"\n in rule_needs_update \n"
  new_rule = rule_args
  existing_rule = parse_rule_output
#puts "\n\n-----------------\n existing rule \n-----------------\n"
#p existing_rule
#puts existing_rule
  Chef::Log.debug("Parsed output: #{existing_rule}")
  diff = []
  new_rule.each do |k, v|
    diff << k unless existing_rule.key? k
    diff << k if v.downcase.gsub('"', '') != existing_rule[k]
  end
  diff << ENABLED unless existing_rule[ENABLED] == YES
  Chef::Log.debug("Updated parameters: #{diff}") unless diff.empty?
  !diff.empty?
end

# Determine if an existing rule is manageable
# Don't attempt to modify built-in rules or rules set by group policy
def system_rule?
#puts"\n in system_rule \n"
  existing_rule = parse_rule_output
  if !existing_rule[GROUPING].empty?
    Chef::Log.error("Firewall rule '#{new_resource.name}' is part of a system group.")
    true
  elsif existing_rule[RULE_SOURCE] != LOCAL_SETTING
    Chef::Log.error("Firewall rule '#{new_resource.name}' is set by group policy.")
    true
  end
  false
end
