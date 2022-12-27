require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$file = File.new('../output/audit_rds.txt', 'w')
$rds_client = Aws::RDS::Client.new
$pass = 0
$fail = 0

def check_Ensure_RDS_encryption()
    list_rds_instances = $rds_client.describe_db_instances({})
    $file.write("<p class='font-semibold text-blue-700'>Database instance: </p>" + list_rds_instances.db_instances.to_s + "\n")
end
#2.3.1 Ensure that encryption is enabled for RDS Instances (Bo)
$file.write("result12.3.1 \nresult2Ensure that encryption is enabled for RDS Instances\n")
if check_Ensure_RDS_encryption() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
$file.write($pass.to_s + ":" + $fail.to_s)

$file.close