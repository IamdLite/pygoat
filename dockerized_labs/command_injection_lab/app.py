from flask import Flask, render_template, request
import subprocess
import os
import re

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key-here"


@app.route("/")
def index():
    """Main page with command injection lab description"""
    return render_template("index.html")


@app.route("/lab1", methods=["GET", "POST"])
def lab1():
    """Lab 1: Name Server Lookup with Command Injection"""
    if request.method == "POST":
        domain = request.form.get("domain", "")
        os_type = request.form.get("os", "")

        # SECURITY FIX (CWE-78): validate the input as a hostname/IP so shell
        # metacharacters (; | & $ ` etc.) and extra arguments are rejected.
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?", domain):
            return render_template(
                "lab1.html", output="Invalid domain name. Only letters, digits, '.' and '-' are allowed."
            )

        tool = "nslookup" if os_type == "win" else "dig"

        try:
            # SECURITY FIX (CWE-78): run with shell=False and a fixed argument
            # vector. User input is passed as a single argv element, so it is
            # treated as data (a hostname) and can never be parsed as a command.
            process = subprocess.Popen(
                [tool, domain], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            output = stdout.decode("utf-8") + stderr.decode("utf-8")
        except Exception as e:
            output = str(e)

        return render_template("lab1.html", output=output)

    return render_template("lab1.html")


@app.route("/lab2", methods=["GET", "POST"])
def lab2():
    """Lab 2: Python eval() Code Execution"""
    if request.method == "POST":
        try:
            # Intentionally vulnerable eval
            expression = request.form.get("val", "")
            output = eval(expression)
            return render_template("lab2.html", output=str(output))
        except Exception as e:
            return render_template("lab2.html", output=str(e))
    return render_template("lab2.html")

@app.route("/health")
def health_check():
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5013, debug=True)
