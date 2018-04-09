#! /usr/bin/env ruby
#
#  check-ssl-certs.rb
#
# DESCRIPTION:
#   Checks the expiration of SSL certificates in a directory
#
# PLATFORMS:
#   Linux
#
# DEPENDENCIES:
#   gem: sensu-plugin
#
# LICENSE:
#   Copyright 2017 Pieter Vogelaar
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

require 'sensu-plugin/check/cli'

class CheckSslCerts < Sensu::Plugin::Check::CLI
  option :ssl_dir,
         description: 'SSL directory',
         short: '-d SSL_DIR',
         long: '--ssl-dir SSL_DIR'

  option :expire_days_critical,
         description: 'Critical when expiration is within X days. Default 7',
         short: '-c EXPIRE_DAYS_CRITICAL',
         long: '--critical EXPIRE_DAYS_CRITICAL',
         proc: proc(&:to_i),
         default: 7

  option :expire_days_warning,
         description: 'Warning when expiration is within X days. Default 14',
         short: '-w EXPIRE_DAYS_WARNING',
         long: '--warning EXPIRE_DAYS_WARNING',
         proc: proc(&:to_i),
         default: 14

  def run
    ssl_dir = config[:ssl_dir]
    expire_days_critical = config[:expire_days_critical]
    expire_days_warning = config[:expire_days_warning]
    expire_sec_critical = expire_days_critical.to_i * 24 * 3600
    expire_sec_warning = expire_days_warning.to_i * 24 * 3600
    status_code = 0

    if File.directory?(ssl_dir)
      Dir.foreach(ssl_dir) do |item|
        next if item == '.' or item == '..'

        `openssl x509 -checkend #{expire_sec_critical} -noout -in #{ssl_dir}/#{item}`
        unless $?.success?
          puts "CRITICAL: Certificate #{item} will expire in less than #{expire_days_critical} days"
          if status_code < 2
            status_code = 2
          end

          next
        end

        `openssl x509 -checkend #{expire_sec_warning} -noout -in #{ssl_dir}/#{item}`
        unless $?.success?
          puts "WARNING: Certificate #{item} will expire in less than #{expire_days_warning} days"
          if status_code < 1
            status_code = 1
          end
        end
      end
    end

    if status_code == 2
      critical 'Certificate(s) are near expiration'
    elsif status_code == 1
      warning 'Certificate(s) are near expiration'
    else
      ok 'Certificate expiration dates are okay'
    end
  end
end
