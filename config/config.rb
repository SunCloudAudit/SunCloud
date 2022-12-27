require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$accessanalyzer_iam = Aws::AccessAnalyzer::Client.new
array_list_analyzers = $accessanalyzer_iam.list_analyzers({})