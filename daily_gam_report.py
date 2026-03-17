import csv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import os
import subprocess
from datetime import datetime, date
import shutil
import GAMDetector

# == Setup == #
SUSPENDED_USERS_FILE = 'non_us_alerts.csv'
SMTP_SERVER = 'smtp-relay.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = "sender_address"
RUNNING_FILE = 'non_us_alerts'
DATE = date.today()
LOG_FILE = 'gam_detector_output.log'
RUNNING_LOGS_FOLDER = 'Running Logs\\'
GAM_CMD = "gam.exe"

#== Output Run Time for GAM Daily Report ==#
print(f"\n# == Start of Daily GAM report at {datetime.now()} == #\n")

#== Get the ID to generate the link to the user's page in Google Admin ==#
def Get_ID(email):
    #id_cmd = f'{GAM_CMD} info user {email} | findstr "Google Unique ID"'
    id_cmd = [GAM_CMD, "info", "user", email]
    result = subprocess.run(id_cmd, shell=True, capture_output=True, text=True)
    print(f'Output in Get_ID: {result}')
    for line in result.stdout.splitlines():
        if "Google Unique ID" in line:
            return line.split(":", 1)[1].strip()

#== Translate the country code to full country name for readability ==#
def Country_Code_Translate(country):
    country_file = "Country_Codes.csv"
    country_lookup = {}
    with open(country_file, newline='', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            code = row['Code'].strip()
            name = row['Country'].strip()
            country_lookup[code] = name
        return country_lookup.get(country, country)
    
#== Creates the HTML table that is sent for the report. Table contains some design elements ==#  
#This creates a dynamic html table by just appending new strings to the existing html since the html message is essneitally compiled as a string. Pretty clever way of doing it (not congratulating myself that was all chatgpt)
def Generate_Table(users_list):
    if not users_list:
        return "<p style=font-size:20px;font-family:Trebuchet MS; text-align: center;'>No Users Reported</p>" #if there was nobody ot suspend that day then return an empty report

    headers = ['User', 'Time', 'IP Address', 'Country or IP Range', 'Google Admin Link'] #Table column names
    table_html = "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse; color:black;'>"
    table_html += "<thead><tr>" + "".join(f"<th>{header}</th>" for header in headers) + "</tr></thead>"
    table_html += "<tbody>"

    for user in users_list:
        row_cells = ""
        for key in headers: 
            value = user.get(key, "")
            if key == 'Google Admin Link':
                cell = f'<td><a href="{value}" target="_blank"><button style="background-color: maroon; color: white">View in Admin</button></a></td>' #For every reported user add a new table line to the html
            else:
                cell = f'<td>{value}</td>'

            row_cells += cell
        
        table_html += f"<tr>{row_cells}</tr>"

    table_html += "</tbody></table>"
    return table_html


def Get_Users():
    users_list = []
    seen = set() #prevent duplicates from appearing in the report
    with open(SUSPENDED_USERS_FILE, newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            nus_email = row.get('actor.email')
            nus_ip = row.get('ipAddress')
            nus_time_str = row.get('id.time')
            nus_country = row.get('country')
            full_country = Country_Code_Translate(nus_country) #Uses the function to convert country code to actual country name
            id = Get_ID(nus_email)
            print(f'User {nus_email} and their ID: {id}')
            url = f"https://admin.google.com/ac/users/{id}"

            print(f'Link for {nus_email} is: {url}')

            #If the user email has not been seen yet add them to the set, but if they have skip this row
            if nus_email in seen:
                continue
            seen.add(nus_email)
            
            users_list.append({
                'User' : nus_email,
                'Time' : GAMDetector.Time_Cleanup(nus_time_str),
                'IP Address' : nus_ip,
                'Country or IP Range' : full_country,
                'Google Admin Link' : url
            })
    return users_list

def Send_Email():
    table = Generate_Table(Get_Users()) #call generate table() and to get the users call Get_Users() within that. Was my idea not chat gpts :)

    #design elements are listed below - sure to change since Nick will complain about my colors
    EMAIL_BODY_HTML = f"""
    <html>
    <body style="background-color:#f6f5f3;">
        <p style="background-color:#f6f5f3; color:maroon; text-align:center; font-family:Trebuchet MS; font-size: 15px"><strong>SUSPENDED USER ACCOUNTS:</strong></p>
        {table}
    </body>
    </html>
    """
    subject = f"***GAM ALERT NIGHTLY REPORT FOR {DATE}***"
    recipients = ['address1', 'address2']
    recipient_str = ', '.join(recipients)

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = SENDER_EMAIL
    message["To"] = recipient_str
    message.attach(MIMEText(EMAIL_BODY_HTML, "html"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.sendmail(SENDER_EMAIL, recipients, message.as_string())
        
# === clear contents of the alert file so we don't receive reports for the same users multiple days === #
def Clear_File():
    file_date = DATE.strftime('%d') #converts date.today to a string and only returns the day
    if os.path.exists(SUSPENDED_USERS_FILE):
        with open(SUSPENDED_USERS_FILE, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            header = reader.fieldnames
        #Write users from Suspended file to a daily csv report with the appended name
        if not rows:
            print('No users found')
        else:
            filename = RUNNING_FILE + file_date + '.csv'
            if os.path.exists(filename):
                with open(filename, 'w', newline='') as day_file:
                    writer = csv.DictWriter(day_file, fieldnames=header)
                    writer.writeheader()
                    writer.writerows(rows)
            else:
                shutil.copy(SUSPENDED_USERS_FILE, filename)

        with open(SUSPENDED_USERS_FILE, 'w', newline='') as out: #Write to the original suspended file with just the headers
            writer = csv.DictWriter(out, fieldnames=header)
            writer.writeheader()
        print(f"[INFO] cleared {SUSPENDED_USERS_FILE} content but retained header.")



if __name__ == '__main__':
    Send_Email()
    Clear_File()

    
    print("#=== End of Daily GAM Report ===#\n")
