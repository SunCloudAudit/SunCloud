from flask import Flask, render_template,  redirect, request, url_for, jsonify
from urllib.parse import unquote
import codecs
import os
import subprocess

app = Flask(__name__)
app.secret_key = "S3cr3t_K3y_0f_S3rv3r"

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/cis')
def cis():
    return render_template('CIS.html')

@app.route('/audit', methods=['POST'])
def audit():
    os.environ["AWS_ACCESS_KEY_ID"] = request.form.get('AWS_ACCESS_KEY_ID')
    os.environ["AWS_SECRET_ACCESS_KEY"] = request.form.get('AWS_SECRET_ACCESS_KEY')
    os.environ["AWS_REGION"] = request.form.get('AWS_REGION')
    run = subprocess.run(["ruby","../config/config.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)   
    error = run.stderr.decode("utf-8")
    if run.returncode == 0:
        return redirect(url_for('home'))
    else:
        return render_template("error.html", error=error)    

@app.route('/home')
def home():
    statuspass = 0
    statusfail = 0
    rule = ["iam", "logging", "monitoring", "networking", "rds", "s3"]
    for i in rule:
        try:
            path = "../output/audit_" + i + ".txt"
            with open(path, 'r') as f:
                last_line = f.readlines()[-1].split(':')
                statuspass += int(last_line[0])
                statusfail += int(last_line[1])
        except Exception as e:
            continue
    return render_template('home.html', statuspass=statuspass, statusfail=statusfail)
@app.route('/iam')
def iam():
    try:
        run = subprocess.run(["ruby","../rules/audit_iam.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error = run.stderr.decode("utf-8")
        if run.returncode == 0:
            result1 = []
            result2 = []
            result3 = []
            result4 = []
            with open('../output/audit_iam.txt', 'r') as f:
                result = f.readlines()
                size_result = len(result) - 1
                arr_result = ""
                for i in range(0, size_result):
                    if "result3" in result[i]:
                        result3.append(result[i][7:])
                        result2.append(arr_result)
                        arr_result = ""
                    else:
                        if "result1" in result[i]:
                            result1.append(result[i][7:])
                        elif "result2" in result[i]:
                            result4.append(result[i][7:])
                        else:
                            arr_result = arr_result + result[i] + "<br/>"
                size = len(result1)
                return render_template('result.html', result1=result1, result4=result4, result2=result2, result3=result3, size = size)
        else:
            return render_template("error.html", error=error)
    except Exception as e:
        return render_template("error.html") 

@app.route('/s3')
def s3():
    try:
        run = subprocess.run(["ruby","../rules/audit_s3.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error = run.stderr.decode("utf-8")
        if run.returncode == 0:
            result1 = []
            result2 = []
            result3 = []
            result4 = []
            with open('../output/audit_s3.txt', 'r') as f:
                result = f.readlines()
                size_result = len(result) - 1
                arr_result = ""
                for i in range(0, size_result):
                    if "result3" in result[i]:
                        result3.append(result[i][7:])
                        result2.append(arr_result)
                        arr_result = ""
                    else:
                        if "result1" in result[i]:
                            result1.append(result[i][7:])
                        elif "result2" in result[i]:
                            result4.append(result[i][7:])
                        else:
                            arr_result = arr_result + result[i] + "<br/>"
                size = len(result1)
                return render_template('result.html', result1=result1, result4=result4, result2=result2, result3=result3, size = size)
        else:
            return render_template("error.html", error=error)
    except Exception as e:
        return render_template("error.html") 

@app.route('/rds')
def rds():
    try:
        run = subprocess.run(["ruby","../rules/audit_rds.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error = run.stderr.decode("utf-8")
        if run.returncode == 0:
            result1 = []
            result2 = []
            result3 = []
            result4 = []
            with open('../output/audit_rds.txt', 'r') as f:
                result = f.readlines()
                size_result = len(result) - 1
                arr_result = ""
                for i in range(0, size_result):
                    if "result3" in result[i]:
                        result3.append(result[i][7:])
                        result2.append(arr_result)
                        arr_result = ""
                    else:
                        if "result1" in result[i]:
                            result1.append(result[i][7:])
                        elif "result2" in result[i]:
                            result4.append(result[i][7:])
                        else:
                            arr_result = arr_result + result[i] + "<br/>"
                size = len(result1)
                return render_template('result.html', result1=result1, result4=result4, result2=result2, result3=result3, size = size)
        else:
            return render_template("error.html", error=error)
    except Exception as e:
        return render_template("error.html") 

@app.route('/ec2')
def ec2():
    try:
        run = subprocess.run(["ruby","../rules/audit_ec2.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error = run.stderr.decode("utf-8")
        if run.returncode == 0:
            result1 = []
            result2 = []
            result3 = []
            result4 = []
            with open('../output/audit_ec2.txt', 'r') as f:
                result = f.readlines()
                size_result = len(result) - 1
                arr_result = ""
                for i in range(0, size_result):
                    if "result3" in result[i]:
                        result3.append(result[i][7:])
                        result2.append(arr_result)
                        arr_result = ""
                    else:
                        if "result1" in result[i]:
                            result1.append(result[i][7:])
                        elif "result2" in result[i]:
                            result4.append(result[i][7:])
                        else:
                            arr_result = arr_result + result[i] + "<br/>"
                size = len(result1)
                return render_template('result.html', result1=result1, result4=result4, result2=result2, result3=result3, size = size)
        else:
            return render_template("error.html", error=error)
    except Exception as e:
        return render_template("error.html") 

@app.route('/logging')
def logging():
    try:
        run = subprocess.run(["ruby","../rules/audit_logging.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error = run.stderr.decode("utf-8")
        if run.returncode == 0:
            result1 = []
            result2 = []
            result3 = []
            result4 = []
            with open('../output/audit_logging.txt', 'r') as f:
                result = f.readlines()
                size_result = len(result) - 1
                arr_result = ""
                for i in range(0, size_result):
                    if "result3" in result[i]:
                        result3.append(result[i][7:])
                        result2.append(arr_result)
                        arr_result = ""
                    else:
                        if "result1" in result[i]:
                            result1.append(result[i][7:])
                        elif "result2" in result[i]:
                            result4.append(result[i][7:])
                        else:
                            arr_result = arr_result + result[i] + "<br/>"
                size = len(result1)
                return render_template('result.html', result1=result1, result4=result4, result2=result2, result3=result3, size = size)
        else:
            return render_template("error.html", error=error)
    except Exception as e:
        return render_template("error.html")    

@app.route('/monitoring')
def monitoring():
    try:
        run = subprocess.run(["ruby","../rules/audit_monitoring.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error = run.stderr.decode("utf-8")
        if run.returncode == 0:
            result1 = []
            result2 = []
            result3 = []
            result4 = []
            with open('../output/audit_monitoring.txt', 'r') as f:
                result = f.readlines()
                size_result = len(result) - 1
                arr_result = ""
                for i in range(0, size_result):
                    if "result3" in result[i]:
                        result3.append(result[i][7:])
                        result2.append(arr_result)
                        arr_result = ""
                    else:
                        if "result1" in result[i]:
                            result1.append(result[i][7:])
                        elif "result2" in result[i]:
                            result4.append(result[i][7:])
                        else:
                            arr_result = arr_result + result[i] + "<br/>"
                size = len(result1)
                return render_template('result.html', result1=result1, result4=result4, result2=result2, result3=result3, size = size)
        else:
            return render_template("error.html", error=error)
    except Exception as e:
        return render_template("error.html")   

@app.route('/networking')
def networking():
    try:
        run = subprocess.run(["ruby","../rules/audit_networking.rb"],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        error = run.stderr.decode("utf-8")
        if run.returncode == 0:
            result1 = []
            result2 = []
            result3 = []
            result4 = []
            with open('../output/audit_networking.txt', 'r') as f:
                result = f.readlines()
                size_result = len(result) - 1
                arr_result = ""
                for i in range(0, size_result):
                    if "result3" in result[i]:
                        result3.append(result[i][7:])
                        result2.append(arr_result)
                        arr_result = ""
                    else:
                        if "result1" in result[i]:
                            result1.append(result[i][7:])
                        elif "result2" in result[i]:
                            result4.append(result[i][7:])
                        else:
                            arr_result = arr_result + result[i] + "<br/>"
                size = len(result1)
                return render_template('result.html', result1=result1, result4=result4, result2=result2, result3=result3, size = size)
        else:
            return render_template("error.html", error=error)
    except Exception as e:
        return render_template("error.html")  

@app.route('/history', methods = ['GET'])
def history():
    result1 = []
    result2 = []
    result3 = []
    result4 = []
    rule = request.args.get('rule')
    if rule != None:
        path = "../output/audit_" + rule + ".txt"
        with open(path, 'r') as f:
            result = f.readlines()
            size_result = len(result) - 1
            arr_result = ""
            for i in range(0, size_result):
                if "result3" in result[i]:
                    result3.append(result[i][7:])
                    result2.append(arr_result)
                    arr_result = ""
                else:
                    if "result1" in result[i]:
                        result1.append(result[i][7:])
                    elif "result2" in result[i]:
                        result4.append(result[i][7:])
                    else:
                        arr_result = arr_result + result[i] + "<br/>"
            size = len(result1)
        return render_template('result.html', rule=rule, result1=result1, result4=result4, result2=result2, result3=result3, size = size)
    else:
        return render_template('history.html')
if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5000, debug=True)
