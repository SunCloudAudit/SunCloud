require 'aws-sdk'
require 'csv'
require 'json'
require 'time'
require 'uri'

$file = File.new('../output/audit_monitoring.txt', 'w')
$cloudtrail_client = Aws::CloudTrail::Client.new
$cloudlog = Aws::CloudWatchLogs::Client.new
$cloudwatch = Aws::CloudWatch::Client.new
$sns = Aws::SNS::Client.new
$pass = 0
$fail = 0

$monitoring_metric = []
def get_loggroup_ClouTrail_enable_all_region()
    resp_descript = $cloudtrail_client.describe_trails({})
    cloudtrail_number = 0
    check = false
    if resp_descript.trail_list.empty? == false
        check = true
    end
    while cloudtrail_number < resp_descript.trail_list.length
        resp_trail_status = $cloudtrail_client.get_trail_status({name: resp_descript.trail_list[cloudtrail_number].name})
        if (resp_descript.trail_list[cloudtrail_number].is_multi_region_trail == true) & (resp_trail_status.is_logging == true)
            resp_selector = $cloudtrail_client.get_event_selectors({trail_name: resp_descript.trail_list[cloudtrail_number].name})
            if resp_selector.event_selectors.nil? == false
                selector_number = 0
                while selector_number < resp_selector.event_selectors.length
                    if resp_selector.event_selectors[selector_number].read_write_type == "All"
                        group_arn = resp_descript.trail_list[cloudtrail_number].cloud_watch_logs_log_group_arn.split(":")
                        resp_metric = $cloudlog.describe_metric_filters({log_group_name: group_arn[6]})
                        number_metric = 0
                        while number_metric < resp_metric.metric_filters.length
                            $monitoring_metric.push(resp_metric.metric_filters[number_metric])
                            number_metric +=1
                        end
                    end
                    selector_number += 1
                end
            else
                check = false
            end
        end
        cloudtrail_number +=1
    end
    return check      
end

get_loggroup_ClouTrail_enable_all_region()
$resp_alarm = $cloudwatch.describe_alarms({})
def check_metric_filter_and_alarm_exist(value_monitor)
    number_filter = 0
    while number_filter < $monitoring_metric.length
        if $monitoring_metric[number_filter].filter_pattern == value_monitor
            $file.write('<span class="font-semibold text-blue-700">Metric name:</span> ' + $monitoring_metric[number_filter].metric_transformations[0].metric_name + "\n")
            number_alarm = 0
            while number_alarm < $resp_alarm.metric_alarms.length                    
                if($monitoring_metric[number_filter].metric_transformations[0].metric_name == $resp_alarm.metric_alarms[number_alarm].metric_name)
                    $file.write('<p class="font-semibold text-blue-700">Cloudtrail log group name:</p>' + $monitoring_metric[number_filter].to_s + "\n")
                    $file.write('<p class="font-semibold text-blue-700">SNS topic name: </p>'+ $resp_alarm.metric_alarms[number_alarm].alarm_actions.to_s + "\n")
                    begin
                        resp_sns = $sns.list_subscriptions_by_topic({topic_arn: $resp_alarm.metric_alarms[number_alarm].alarm_actions[0]})
                    rescue
                        $file.write("None\n")
                    else
                        $file.write('<p class="font-semibold text-blue-700">Subscription: </p>' + resp_sns.subscriptions.to_s)
                    end
                    $file.write("\n")
                end
                number_alarm +=1
            end
        end
        number_filter += 1
    end
end

# 4.1 
$file.write("result14.1\nresult2Ensure a log metric filter and alarm exist for unauthorized API calls\n")
if check_metric_filter_and_alarm_exist('{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.2
$file.write("result14.2\nresult2CloudWatch log metric filter and alarm for Management Console sign-in without MFA\n")
if check_metric_filter_and_alarm_exist('{ $.eventName = ConsoleLogin && $.additionalEventData.MFAUsed = "No" }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.3
$file.write("result14.3\nresult2CloudWatch log metric filter and alarm for usage of root account should be configured\n")
if check_metric_filter_and_alarm_exist('{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.4
$file.write("result14.4\nresult2CloudWatch log metric filter and alarm for IAM policy changes should be configured\n")
if check_metric_filter_and_alarm_exist('{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.5
$file.write("result14.5\nresult2CloudWatch log metric filter and alarm for CloudTrail configuration changes should be configured\n")
if check_metric_filter_and_alarm_exist('{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.6
$file.write("result14.6\nresult2CloudWatch log metric filter and alarm for Management Console authentication failures should be configured\n")
if check_metric_filter_and_alarm_exist('{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.7
$file.write("result14.7\nresult2Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs\n")
if check_metric_filter_and_alarm_exist('{ $.eventSource = kms* && $.errorMessage = "* is pending deletion."}') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.8
$file.write("result14.8\nresult2Ensure a log metric filter and alarm exist for S3 bucket policy changes\n")
if check_metric_filter_and_alarm_exist('{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.9
$file.write("result14.9\nresult2Ensure a log metric filter and alarm exist for AWS Config configuration changes\n")
if check_metric_filter_and_alarm_exist('{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder)||($.eventName = DeleteDeliveryChannel)||($.eventName = PutDeliveryChannel)||($.eventName = PutConfigurationRecorder)) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.10
$file.write("result14.10\nresult2CloudWatch log metric filter and alarm for VPC security group changes should be configured\n")
if check_metric_filter_and_alarm_exist('{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.11
$file.write("result14.11\nresult2CloudWatch log metric filter and alarm for changes to VPC NACLs should be configured\n")
if check_metric_filter_and_alarm_exist('{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.12
$file.write("result14.12\nresult2CloudWatch log metric filter and alarm for changes to VPC network gateways should be configured\n")
if check_metric_filter_and_alarm_exist('{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.13
$file.write("result14.13\nresult2CloudWatch log metric filter and alarm for VPC route table changes should be configured\n")
if check_metric_filter_and_alarm_exist('{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.14
$file.write("result14.14\nresult2CloudWatch log metric filter and alarm for VPC changes should be configured\n")
if check_metric_filter_and_alarm_exist('{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
# 4.15
$file.write("result14.15\nresult2Ensure a log metric filter and alarm exists for AWS Organizations changes\n")
if check_metric_filter_and_alarm_exist('{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }') == true
    $pass += 1 
    $file.write("result3<span class='text-green-700 bg-green-100'>Pass</span>\n")
else
    $fail += 1 
    $file.write("result3<span class='text-red-700 bg-red-100'>Fail</span>\n")
end
$file.write($pass.to_s + ":" + $fail.to_s)
$file.close