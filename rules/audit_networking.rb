require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$file = File.new('../output/audit_networking.txt', 'w')
$network_ec2 = Aws::EC2::Client.new
$pass = 0
$fail = 0

def check_routing_tables_for_VPC_are_least_access()
    resp_router = $network_ec2.describe_route_tables({})
    $file.write("<p class='font-semibold text-blue-700'>Router: </p>" + resp_router.to_s + "\n")
end

# 5.4 Ensure routing tables for VPC peering are "least access" 
$file.write("result15.4 \nresult2Ensure routing tables for VPC peering are \"least access\"\n")
if check_routing_tables_for_VPC_are_least_access() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
$file.write($pass.to_s + ":" + $fail.to_s)
$file.close