# Suncloud
## Description
SunCloud is a tool developed and perfected to perform audits
AWS cloud computing automation. SunCloud is built upon the CIS standard for the AWS platform and the AWS SDK library for the Ruby language. SunCloud's automated audits provide comprehensive risk detection: misconfiguration, identity and access management risks, behavior
abnormal behavior… The tool can audit most of the proposed rules according to CIS standards corresponding to services such as: IAM, EC2, S3, Logging, Networking, Monitoring. The tool also has a Web interface that makes the process more intuitive and user-friendly. To use the tool, users only need to have an AWS account, perform login through SunCloud and perform audit functions. The tool will automatically check and return the results, then users can export the reports as PDF.
Functions of the tool:
- Log in
- View documents CIS Benmark
- Auditing IAM
- Auditing EC2
- Auditing S3
- Logging audit
- Networking Audit
- Monitoring Audit
- View audit history
- Save audit results to file
## Scope and Limitations
The tool is built for all users of the AWS cloud platform. The tool can run on many different operating systems such as Windows, Linux, etc.
# Installation
## Install AWS-SDK
```
gem install aws-sdk
```

## Install Ruby
Install Ruby 3 at  https://rubyinstaller.org/
## Clone this project
```
git clone https://github.com/SunCloudAudit/SunCloud
```
## Install Flask
```
cd server
pip install -r requirements.txt
flask --version
```
## Run Web-interface
```
cd server
python3 app.py
```
Server run at http://localhost:5000

![Screenshot from 2023-05-24 11-19-18](https://github.com/SunCloudAudit/SunCloud/assets/69457314/65f36d5c-5756-4533-a2ad-456f24199663)




