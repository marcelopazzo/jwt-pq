# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

desc "Compile the liboqs extension"
task :compile do
  Dir.chdir("ext/jwt/pq") do
    ruby "extconf.rb"
    sh "make"
  end
end

task default: :spec
