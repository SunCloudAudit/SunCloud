require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$file = File.new('../output/audit_s3.txt', 'w')
$client_s3 = Aws::S3::Client.new
$control_s3 = Aws::S3Control::Client.new
$STS_client = Aws::STS::Client.new
$pass = 0
$fail = 0

def check_buckets_employ_encryption()
    array_list_bucket = $client_s3.list_buckets
    bucket_number = 0
    check = false
    if array_list_bucket.buckets.empty? == false
        check = true
    end
    $file.write("<span class='font-semibold text-blue-700'>Bucket: </span>\n")
    while bucket_number < array_list_bucket.buckets.length
        begin
            resp_bucket_encryption = $client_s3.get_bucket_encryption({bucket: array_list_bucket.buckets[bucket_number].name})
        rescue
            $file.write("\t<p class='font-semibold text-blue-700'>" + array_list_bucket.buckets[bucket_number].name + "</p>: Nope\n")
            check = false
        else
            $file.write("\t<p class='font-semibold text-blue-700'>" + array_list_bucket.buckets[bucket_number].name + "</p> : "+resp_bucket_encryption.server_side_encryption_configuration.rules[0].apply_server_side_encryption_by_default.sse_algorithm + "\n")
        end
        bucket_number +=1
    end
    return check
end

def check_deny_HTTP_requests()
    array_list_bucket = $client_s3.list_buckets
    bucket_number = 0
    check = false
    if array_list_bucket.buckets.empty? == false
        check = true
    end
    while bucket_number < array_list_bucket.buckets.length
        begin
            resp_bucket_policy = $client_s3.get_bucket_policy({bucket: array_list_bucket.buckets[bucket_number].name})
        rescue
            check = false
        else
            $file.write("<p class='font-semibold text-blue-700'>" + array_list_bucket.buckets[bucket_number].name + "</p>:")
            $file.write(resp_bucket_policy.to_h)
        end
        bucket_number +=1
    end
    return check    
end

def check_MFA_Delete_enable()
    array_list_bucket = $client_s3.list_buckets
    bucket_number = 0
    check = false
    if array_list_bucket.buckets.empty? == false
        check = true
    end
    $file.write("<span class='font-semibold text-blue-700'>Bucket: </span>\n")
    while bucket_number < array_list_bucket.buckets.length
        $file.write("\t<span class='font-semibold text-blue-700'>" + array_list_bucket.buckets[bucket_number].name + "</span>\n")
        resp_bucket_MFA = $client_s3.get_bucket_versioning({bucket: array_list_bucket.buckets[bucket_number].name})
        $file.write("<p class='font-semibold text-blue-700'>Bucket MFA status: </p>" + resp_bucket_MFA.status.to_s + "\n")
        if resp_bucket_MFA.status.nil?
             check = false
        else
            $file.write("<p class='font-semibold text-blue-700'>Bucket MFA delete: </p>" + resp_bucket_MFA.mfa_delete.to_s + "\n")
            if resp_bucket_MFA.mfa_delete.nil?
                check = false
            else
                if(resp_bucket_MFA.status != "Enabled") | (resp_bucket_MFA.mfa_delete != "Enabled")
                    check = false
                end
            end
        end
        bucket_number +=1
    end
    return check      
end

def check_Ensure_Block_public_access_Bucket()
    array_list_bucket = $client_s3.list_buckets
    bucket_number = 0
    check = false
    if array_list_bucket.buckets.empty? == false
        check = true
    end
    $file.write("<span class='font-semibold text-blue-700'>Bucket: </span>\n")
    while bucket_number < array_list_bucket.buckets.length
        resp_bucket_access_block = $client_s3.get_public_access_block({bucket: array_list_bucket.buckets[bucket_number].name})
        begin
            resp_public_access_block = resp_bucket_access_block.public_access_block_configuration
        rescue
            check = false
        else
            $file.write("\t<p class='font-semibold text-blue-700'>" + array_list_bucket.buckets[bucket_number].name + "</p>:")
            $file.write("BlockPublicAcls: " + resp_public_access_block.block_public_acls.to_s +
                        ", IgnorePublicAcls: " + resp_public_access_block.ignore_public_acls.to_s +
                        ", BlockPublicPolicy: " + resp_public_access_block.block_public_policy.to_s +
                        ", RestrictPublicBuckets: " + resp_public_access_block.restrict_public_buckets.to_s + " \n")
            if (resp_public_access_block.block_public_acls != true) | (resp_public_access_block.ignore_public_acls !=true) | (resp_public_access_block.block_public_policy != true) | (resp_public_access_block.restrict_public_buckets != true)
                check = false
            end
        end
        bucket_number +=1
    end
    return check     
end

def check_Ensure_Block_public_access_Account()
    resp_block = $control_s3.get_public_access_block({account_id: $STS_client.get_caller_identity({}).account})
    $file.write("<p class='font-semibold text-blue-700'>Account ID: </p>" + $STS_client.get_caller_identity({}).account + "\n")
    begin
        resp_public_access_block = resp_block.public_access_block_configuration
    rescue
        check = false
    else
        $file.write("BlockPublicAcls: " + resp_public_access_block.block_public_acls.to_s +
        ", IgnorePublicAcls: " + resp_public_access_block.ignore_public_acls.to_s +
        ", BlockPublicPolicy: " + resp_public_access_block.block_public_policy.to_s +
        ", RestrictPublicBuckets: " + resp_public_access_block.restrict_public_buckets.to_s + " \n")
        if (resp_public_access_block.block_public_acls == true) & (resp_public_access_block.ignore_public_acls ==true) & (resp_public_access_block.block_public_policy == true) & (resp_public_access_block.restrict_public_buckets == true)
            check = true
        else
            check = false
        end
    end
    return check
end

$file.write("result12.1.1 \nresult2Ensure all S3 buckets employ encryption-at-rest\n")
if check_buckets_employ_encryption() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result12.1.3 \nresult2Ensure MFA Delete is enable on S3 buckets\n")
if check_MFA_Delete_enable() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result12.1.6 \nresult2Ensure that S3 Buckets are configured with 'Block public access (account settings)'\n")
if check_Ensure_Block_public_access_Account() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
$file.write($pass.to_s + ":" + $fail.to_s)

$file.close
