require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$file = File.new('../output/audit_iam.txt', 'w')
$client_iam = Aws::IAM::Client.new
$password_policy_iam = Aws::IAM::AccountPasswordPolicy.new
$accessanalyzer_iam = Aws::AccessAnalyzer::Client.new
set_generate_credential_report = $client_iam.generate_credential_report
resp_credential_report = $client_iam.get_credential_report
resp_account_summary = $client_iam.get_account_summary
keys = ["user","arn","user_creation_time","password_enabled","password_last_used",
        "password_last_changed","password_next_rotation","mfa_active","access_key_1_active",
        "access_key_1_last_rotated","access_key_1_last_used_date","access_key_1_last_used_region",
        "access_key_1_last_used_service","access_key_2_active","access_key_2_last_rotated",
        "access_key_2_last_used_date","access_key_2_last_used_region","access_key_2_last_used_service",
        "cert_1_active","cert_1_last_rotated","cert_2_active","cert_2_last_rotated"]
$resp_credential_report_hash = CSV.parse(resp_credential_report.content).map {|a| Hash[ keys.zip(a) ] }
$pass = 0
$fail = 0

def check_time(user, get_time)
    return (Time.now() - Time.parse($resp_credential_report_hash[user][get_time]))/86400
end
def check_mfa_report()
    user = 2
    check = true
    $file.write("<span class='font-semibold text-blue-700'>User: </span>\n")
    while user < $resp_credential_report_hash.length
        $file.write("\t" + $resp_credential_report_hash[user]["user"] + ": \n")
        $file.write("\t\t<p class='font-semibold text-blue-700'>Password enabled:</p> " + $resp_credential_report_hash[user]["password_enabled"] + "\n")
        if $resp_credential_report_hash[user]["password_enabled"] == "true"
            $file.write("\t\t<p class='font-semibold text-blue-700'>Mfa active: </p>" + $resp_credential_report_hash[user]["mfa_active"] + "\n")
            if $resp_credential_report_hash[user]["mfa_active"] == "true"
                check = true
            else
                return false
            end
        end 
        user += 1
    end
    return check
end

def check_ack_last_use()
    user = 2
    check = true
    $file.write("<span class='font-semibold text-blue-700'>User: </span>\n")
    while user < $resp_credential_report_hash.length
        $file.write("\t" + $resp_credential_report_hash[user]["user"] + ": \n")
        $file.write("\t\t<p class='font-semibold text-blue-700'>Password enabled:</p> " + $resp_credential_report_hash[user]["password_enabled"] + "\n")
        if $resp_credential_report_hash[user]["password_enabled"] == "true"
            $file.write("\t\t<p class='font-semibold text-blue-700'>The time access key last used:</p> " + $resp_credential_report_hash[user]["access_key_last_used_date"].to_s + "\n")
            if $resp_credential_report_hash[user]["access_key_last_used_date"] == "N/A"
                return false
            else
                check = true
            end
        end
        user += 1
    end
    return check
end

def check_credentials_unused_time(param1, value1, param2, value2, param3, value3)
    user = 2
    check = true
    $file.write("<span class='font-semibold text-blue-700'>User: </span>\n")
    while user < $resp_credential_report_hash.length
        $file.write("\t" + $resp_credential_report_hash[user]["user"] + ": \n")
        $file.write("\t\t" + param1 + ": " + $resp_credential_report_hash[user][param1] + "\n")
        if $resp_credential_report_hash[user][param1] == value1
            $file.write("\t\t" + param2 + ": " + $resp_credential_report_hash[user][param2] + "\n")
            if $resp_credential_report_hash[user][param2] == value2
                $file.write("\t\t" + param3 + ": " + $resp_credential_report_hash[user][param3] + "\n")
                if $resp_credential_report_hash[user][param3] == value3
                    return false
                else                   
                    if check_time(user, param3) <= 45
                        check = true
                    else
                        return false
                    end
                end
            else                
                if check_time(user,param2) <= 45
                    check = true
                else
                    return false
                end
            end
        end
        user +=1
    end
    return check
end
def check_credentials_unused()
    check = false
    check = check_credentials_unused_time("password_enabled", "true", "password_last_used", "no_information","password_last_changed", "not_supported") & check_credentials_unused_time("access_key_1_active", "true", "access_key_1_last_used_date", "N/A", "access_key_1_last_rotated", "N/A") & check_credentials_unused_time("access_key_2_active", "true", "access_key_2_last_used_date", "N/A", "access_key_2_last_rotated", "N/A")
    return check
end

def check_active_accesskey()
    user = 2
    check = true
    $file.write("<span class='font-semibold text-blue-700'>User: </span>\n")
    while user < $resp_credential_report_hash.length
        $file.write("\t" + $resp_credential_report_hash[user]["user"] + ": \n")
        resp = $client_iam.list_access_keys({user_name: $resp_credential_report_hash[user]["user"]})
        array_key = 0
        count_key = 0
        while array_key < resp.access_key_metadata.length
            $file.write("\t\t" + resp.access_key_metadata[array_key].access_key_id + ": " + resp.access_key_metadata[array_key].status + "\n")
            if resp.access_key_metadata[array_key].status = "Active"
                count_key += 1
            end
            if count_key <= 1
                check = true
            else
                check = false
            end
            array_key +=1
        end
        user +=1
    end
    return check
end
def check_rotated_accesskey()
    user = 2
    check = true
    $file.write("<span class='font-semibold text-blue-700'>User: </span>\n")
    while user < $resp_credential_report_hash.length
        $file.write("\t" + $resp_credential_report_hash[user]["user"] + ": \n")
        if $resp_credential_report_hash[user]["access_key_1_last_rotated"] != "N/A"
            $file.write("<p class='font-semibold text-blue-700'>The last time Access keys are rotated: </p>"+ $resp_credential_report_hash[user]["access_key_1_last_rotated"] + "\n")
            if check_time(user, "access_key_1_last_rotated") <= 90
                return true
            else
                return false
            end
        end
        user += 1
    end
    return check
end
def check_only_group_policy()  
    user = 2
    check = true
    $file.write("<span class='font-semibold text-blue-700'>User:</span> \n")
    while user < $resp_credential_report_hash.length
        $file.write("\t\n" + $resp_credential_report_hash[user]["user"] + ": \n")
        resp_attached = $client_iam.list_attached_user_policies({user_name: $resp_credential_report_hash[user]["user"]})
        $file.write("<span class='font-semibold text-blue-700'>- Attached policies: " + resp_attached.attached_policies.to_s + "</span>\n")
        if resp_attached.attached_policies.empty?
            $file.write("<span class='font-semibold text-blue-700'>- List user policies: \n\t" + $client_iam.list_user_policies({user_name: $resp_credential_report_hash[user]["user"]}).to_s + "</span>")
            resp = $client_iam.list_user_policies({user_name: $resp_credential_report_hash[user]["user"]})
            if resp.policy_names.empty?
                check = true
            else
                check = false
            end
        else
            check=false
        end
        user += 1
    end
    return check 
end

def check_allow_full()
    array_list_policies = $client_iam.list_policies({only_attached: "true"})
    array_arn = array_list_policies.policies
    arn_number = 0
    check = true
    while arn_number < array_arn.length
        resp_policy_version = $client_iam.get_policy_version({policy_arn: array_arn[arn_number].arn,version_id: array_arn[arn_number].default_version_id})
        unescape_resp = CGI.escape(resp_policy_version.policy_version.document)
    #    $file.write("Policy version: " + unescape_resp + "\n")
        var_full_access1 = '"Effect": "Allow"'
        var_full_access2 = '"Action": "*"'
        var_full_access3 = '"Resource": "*"'           
        if (unescape_resp.include? var_full_access1) && (unescape_resp.include? var_full_access2) && (unescape_resp.include? var_full_access3)
            $file.write("<p class='font-semibold text-blue-700'>Policy version:</p> " + unescape_resp + "\n")
            check = false
        end
        arn_number += 1
    end
    return check
end

def check_expired_SSLTLS()
    array_list_cert = $client_iam.list_server_certificates({})
    cert_number = 0
    check = true
    $file.write("<span class='font-semibold text-blue-700'>List server certificates:</span>\n\t" + array_list_cert.server_certificate_metadata_list.to_s + "\n")
    while cert_number < array_list_cert.server_certificate_metadata_list.length
        $file.write(array_list_cert.server_certificate_metadata_list[cert_number].server_certificate_name)
        check = false
        cert_number +=1
    end
    return check
end

def check_IAM_Access_enable_all_region()
    check = false
    array_list_analyzers = $accessanalyzer_iam.list_analyzers({})
    analyzers_number = 0
    if array_list_analyzers.analyzers.empty? == false
        check = true
    end
    $file.write("<span class='font-semibold text-blue-700'>List analyzers: </span>\n")
    while analyzers_number < array_list_analyzers.analyzers.length
        $file.write("\t<p class='font-semibold text-blue-700'>" + array_list_analyzers.analyzers[analyzers_number].name + "</p>:" + array_list_analyzers.analyzers[analyzers_number].status + "\n")
        if(array_list_analyzers.analyzers[analyzers_number].status != "ACTIVE")
            check = false
        end
        analyzers_number +=1
    end
    return check
end

$file.write("result11.4 \nresult2Ensure no 'root' user account access key exists\n")
$file.write("Account Access Keys Present: " + $client_iam.get_account_summary.summary_map["AccountAccessKeysPresent"].to_s + "\n")
if $client_iam.get_account_summary.summary_map["AccountAccessKeysPresent"] == 0
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result11.5 \nresult2Ensure MFA is enabled for the 'root' user account\n")
$file.write("Account MFA Enabled: " + resp_account_summary.summary_map["AccountMFAEnabled"].to_s + "\n")
if resp_account_summary.summary_map["AccountMFAEnabled"] == 1
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result11.6 \nresult2Ensure hardware MFA is enabled for the 'root' user account \n")
$file.write("Account MFA Enabled: " + resp_account_summary.summary_map["AccountMFAEnabled"].to_s + "\n")
$file.write("Mfa device: " + $client_iam.list_mfa_devices.mfa_devices.to_s + "\n")
if resp_account_summary.summary_map["AccountMFAEnabled"] == 1 && $client_iam.list_mfa_devices.mfa_devices.length != 0
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result11.8 \nresult2Ensure IAM password policy requires minimum length of 14 or greater\n")
$file.write("Minimum length of Password: " + $password_policy_iam.minimum_password_length.to_s + "\n")
if $password_policy_iam.minimum_password_length >= 14
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

$file.write("result11.9 \nresult2Ensure IAM password policy prevents password reuse\n")
$file.write("Prevents password reuse: " + $password_policy_iam.password_reuse_prevention.to_s + "\n")
if $password_policy_iam.password_reuse_prevention == 24
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

# result11.10
$file.write("result11.10 \nresult2Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password\n")
if check_mfa_report() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# result11.11 
$file.write("result11.11 \nresult2Do not setup access keys during initial user setup for all IAM users that have a console password\n")
if check_ack_last_use() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end    
# result11.12
$file.write("result11.12 \nresult2Ensure credentials unused for 45 days or greater are disabled\n")
if check_credentials_unused() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

# result11.13
$file.write("result11.13 \nresult2Ensure there is only one active access key available for any single
IAM user\n")
if check_active_accesskey() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

#result11.14
$file.write("result11.14 \nresult2Ensure access keys are rotated every 90 days or less\n")
if check_rotated_accesskey() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

#result11.15
$file.write("result11.15 \nresult2Ensure IAM Users Receive Permissions Only Through Groups\n")
if check_only_group_policy() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

#result11.16
$file.write("result11.16 \nresult2Ensure IAM policies that allow full '*:*' administrative privileges are not attached\n")
if check_allow_full() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

#result11.19
$file.write("result11.19 \nresult2Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed\n")
if check_expired_SSLTLS() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end

#result11.20
$file.write("result11.20 \nresult2Ensure that IAM Access analyzer is enabled for all regions\n")
if check_IAM_Access_enable_all_region() == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
$file.write($pass.to_s + ":" + $fail.to_s)
$file.close