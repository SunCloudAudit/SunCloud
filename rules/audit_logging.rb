require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$file = File.new('../output/audit_logging.txt', 'w')
$cloudtrail_client = Aws::CloudTrail::Client.new
$client_s3 = Aws::S3::Client.new
$configservice = Aws::ConfigService::Client.new
$kms = Aws::KMS::Client.new
$pass = 0
$fail = 0

def check_ClouTrail_enable_all_region()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        resp_trail_status = $cloudtrail_client.get_trail_status({name: resp_descript.trail_list[cloudtrail_number].name})
        resp_trail_event = $cloudtrail_client.get_event_selectors({trail_name: resp_descript.trail_list[cloudtrail_number].name})
        $file.write(resp_descript.trail_list[cloudtrail_number].is_multi_region_trail.to_s + "\n")
        $file.write(resp_descript.trail_list[cloudtrail_number].name + "\n")
        $file.write(resp_trail_status.is_logging.to_s + "\n")
        $file.write(resp_trail_event.event_selectors)
        $file.write("\n")
        if (resp_descript.trail_list[cloudtrail_number].is_multi_region_trail != true) | (resp_trail_status.is_logging != true)
            check = false
        end
        cloudtrail_number +=1
    end
    return check      
end

def check_ClouTrail_log_file_enable()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        $file.write("<p class='font-semibold text-blue-700'>Cloudtrail name: </p>" + resp_descript.trail_list[cloudtrail_number].name + "\n")
        $file.write("<p class='font-semibold text-blue-700'>ClouTrail log file enable: </p>" + resp_descript.trail_list[cloudtrail_number].log_file_validation_enabled.to_s + "\n")
        $file.write("\n")
        if resp_descript.trail_list[cloudtrail_number].log_file_validation_enabled != true
            check = false
        end
        cloudtrail_number +=1
    end
    return check     
end

def check_S3_bucket_used_to_store_CloudTrail()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        $file.write("<p class='font-semibold text-blue-700'>Cloudtrail name: </p>" + resp_descript.trail_list[cloudtrail_number].name + "\n")
        $file.write("<p class='font-semibold text-blue-700'>Bucket name: </p>" + resp_descript.trail_list[cloudtrail_number].s3_bucket_name + "\n")
        resp_bucket_name = resp_descript.trail_list[cloudtrail_number].s3_bucket_name
        $file.write("\n")
        resp_bucket_acl = $client_s3.get_bucket_acl({bucket: resp_bucket_name})
        $file.write("<p class='font-semibold text-blue-700'>Bucket acl grants: </p>" + resp_bucket_acl.grants + "\n")
        resp_bucket_policy = $client_s3.get_bucket_policy({bucket: resp_bucket_name})
        $file.write("<p class='font-semibold text-blue-700'>Bucket policy: </p>" + resp_bucket_policy.policy.to_s + "\n")
        cloudtrail_number +=1
    end
    return check     
end

def check_CloudTrail_intergrated_with_CloudWatch()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        $file.write("<p class='font-semibold text-blue-700'>Cloudtrail name: </p>" + resp_descript.trail_list[cloudtrail_number].name + "\n")
        $file.write("<p class='font-semibold text-blue-700'>Cloudwatch log group arn: </p>" + resp_descript.trail_list[cloudtrail_number].cloud_watch_logs_log_group_arn.to_s + "\n")
        if resp_descript.trail_list[cloudtrail_number].cloud_watch_logs_log_group_arn.nil? == false
            resp_status = $cloudtrail_client.get_trail_status({name: resp_descript.trail_list[cloudtrail_number].name})
            $file.write("<p class='font-semibold text-blue-700'>Latest delivery time: </p>" + resp_status.latest_delivery_time.to_s + "\n")
            check_time = (Time.now() - resp_status.latest_delivery_time)/86400
            if(check_time > 1)
                check = false
            end
        else
            check = false
        end
        cloudtrail_number +=1
    end
    return check    
end

def check_AWS_config_enable_all_regions()
    describe_config = $configservice.describe_configuration_recorders({})
    config_number = 0
    check = false
    if describe_config.configuration_recorders.empty? == false
        check = true
    end
    while config_number < describe_config.configuration_recorders.length
        $file.write("<p class='font-semibold text-blue-700'>All supported: </p>" + describe_config.configuration_recorders[config_number].recording_group.all_supported.to_s + ", Include global resource types: " + describe_config.configuration_recorders[config_number].recording_group.include_global_resource_types.to_s + "\n")
        if(describe_config.configuration_recorders[config_number].recording_group.all_supported == true) & (describe_config.configuration_recorders[config_number].recording_group.include_global_resource_types == true)
            describe_config_status = $configservice.describe_configuration_recorder_status({configuration_recorder_names: [describe_config.configuration_recorders[config_number].name]})
            $file.write("<p class='font-semibold text-blue-700'>Recording: </p>" + describe_config_status.configuration_recorders_status[0].recording.to_s + ", Last status: " + describe_config_status.configuration_recorders_status[0].last_status.to_s + "\n")
            if (describe_config_status.configuration_recorders_status[0].recording == true) & (describe_config_status.configuration_recorders_status[0].last_status == "Success")
                return true
            else
                check = false
            end
        else
            check = false
        end
        config_number +=1
    end
    return check    
end

def check_S3_bucket_logging_enable_on_cloudtrail()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        $file.write("<p class='font-semibold text-blue-700'>Cloudtrail name: </p>" + resp_descript.trail_list[cloudtrail_number].name + "\n")
        resp_bucket_name = resp_descript.trail_list[cloudtrail_number].s3_bucket_name
        resp_bucket_logging = $client_s3.get_bucket_logging({bucket: resp_bucket_name})
        $file.write("<p class='font-semibold text-blue-700'>S3 bucket logging enable: </p>" + resp_bucket_logging.logging_enabled.to_s + "\n")
        if resp_bucket_logging.logging_enabled.nil? == true
             check = false
        end
        cloudtrail_number +=1
    end
    return check      
end

def check_CloudTrail_encrypted_used_KMS_CMKs()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        $file.write("<p class='font-semibold text-blue-700'>Cloudtrail name: </p>" + resp_descript.trail_list[cloudtrail_number].name + "\n")
        $file.write("<p class='font-semibold text-blue-700'>CloudTrail encrypted used KMS CMKs: </p>" + resp_descript.trail_list[cloudtrail_number].kms_key_id.to_s + "\n")
        if resp_descript.trail_list[cloudtrail_number].kms_key_id.nil? == true
             check = false
        end
        cloudtrail_number +=1
    end
    return check     
end

def check_rotation_CMKs_enable()
    resp_kms = $kms.list_keys({})
    kms_number = 0
    check = false
    if resp_kms.keys.empty? == false
        check = true
    end
    $file.write("<p class='font-semibold text-blue-700'>KMS keys: </p>" + resp_kms.keys.to_s + "\n")
    while kms_number < resp_kms.keys.length
        $file.write("<p class='font-semibold text-blue-700'>Key id: </p>" + resp_kms.keys[kms_number].key_id + "\n")
        resp_rotation = $kms.get_key_rotation_status({key_id: resp_kms.keys[kms_number].key_id})
        $file.write("<p class='font-semibold text-blue-700'>Key rotation enabled: </p>" + resp_rotation.key_rotation_enabled.to_s + "\n")
        if resp_rotation.key_rotation_enabled == false
             check = false
        end
        kms_number +=1
    end
    return check    
end

def check_Object_logging_for_read_write_events_enable()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        $file.write("<p class='font-semibold text-blue-700'>Cloudtrail name: </p>" + resp_descript.trail_list[cloudtrail_number].name + "\n")
        resp_selector = $cloudtrail_client.get_event_selectors({trail_name: resp_descript.trail_list[cloudtrail_number].name})
        $file.write("E<p class='font-semibold text-blue-700'>vent selector: </p>" + resp_selector.event_selectors + "\n")
        if resp_selector.event_selectors.nil? == false
            selector_number = 0
            while selector_number < resp_selector.event_selectors.length
                $file.write("<p class='font-semibold text-blue-700'>Logging values : </p>" + resp_selector.event_selectors[selector_number].data_resources[0].values + "\n")
                $file.write("<p class='font-semibold text-blue-700'>Logging events : </p>" + resp_selector.event_selectors[selector_number].read_write_type + "\n")
                selector_number += 1
            end
        else
             check = false
        end
        cloudtrail_number +=1
    end
    return check     
end

$file.write("result13.2 \nresult2Ensure CloudTrail log file validation is enabled\n")
if check_ClouTrail_log_file_enable() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result13.4 \nresult2Ensure CloudTrail trails are integrated with CloudWatch Logs\n")
if check_CloudTrail_intergrated_with_CloudWatch() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result13.5 \nresult2Ensure AWS Config is enabled in all regions\n")
if check_AWS_config_enable_all_regions() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result13.6 \nresult2Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket\n")
if check_S3_bucket_logging_enable_on_cloudtrail() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

#3.7 \nresult2Ensure CloudTrail logs are encrypted at rest using KMS CMKs
$file.write("result13.7 \nresult2Ensure CloudTrail logs are encrypted at rest using KMS CMKs\n")
if check_CloudTrail_encrypted_used_KMS_CMKs() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result13.8 \nresult2Ensure rotation for customer created CMKs is enable\n")
if check_rotation_CMKs_enable() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write($pass.to_s + ":" + $fail.to_s)
$file.close
