require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$file = File.new('../output/audit_ec2.txt', 'w')
$ec2_client = Aws::EC2::Client.new
$pass = 0
$fail = 0

def check_Ensure_EBS_encryption()
  check = false
  resp_ebs_encryption = $ec2_client.get_ebs_encryption_by_default({dry_run: false})
  $file.write("<p class='font-semibold text-blue-700'>Ebs encryption by default: </p>" + resp_ebs_encryption.ebs_encryption_by_default.to_s + "\n")
  if resp_ebs_encryption.ebs_encryption_by_default == true
    check = true
  else
    check = false
  end
  return check
end

#2.2.1 Ensure EBS volume encryption is enabled (Full quyen EC2)
$file.write("result12.2.1 \nresult2Ensure EBS volume encryption is enabled\n")
if check_Ensure_EBS_encryption() == true
  $pass += 1
  $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
  $fail += 1
  $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write($pass.to_s + ":" + $fail.to_s)
$file.close