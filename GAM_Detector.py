import csv
import subprocess
import requests
from datetime import datetime, UTC, timedelta
import time
import os
import smtplib
import io
import keyring
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ipaddress
import sys
import json

# == Debugging == #
log_path = "PATH"
sys.stdout = open(log_path,'a')
sys.stderr = sys.stdout
print(f'Starting GAMDetector Output time: {datetime.now()}')

# === CONFIGURATION ===#
IPINFO_TOKEN = 'API_TOKEN_STRING'
GAM_CMD = "gam.exe"  # Full path to GAM if not in PATH
ALERT_FILE = "PATH_TO_FILE"
LAST_CHECK_FILE = "PATH_TO_FILE"
PARENT_EMAILS_SHEET = "PATH_TO_FILE"
VPN_IP_Sheet = "PATH_TO_FILE"
CACHE_PATH = "PATH_TO_FILE"
TEMP_PATH = "PATH_TO_FILE"
NOW = datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z') 

# === SMTP Settings ===#
smtp_server = 'smtp-relay.gmail.com'
smtp_port = 587
sender_email = "SENDER_ADDRESS"

# == Subprocess == #
host = "SERVER_ADDRESS"
admin_username = "ADMIN_USERNAME"
admin_password = keyring.get_password(admin_username, admin_username) #proper practice to store credentials in Windows Credential Manager and use the keyring library to access the password
local_path = "PATH_TO_FILE"
Remote_Path = "SERVER_AND_FILE_PATH"

#== Read in VPN IP Addresses ==#
#This one stores all of the known IP subnets associated with VPNs into memory, so that the csv does not need to be repeatedly opened
VPN_RANGES = []
with open(VPN_IP_Sheet, newline="", encoding='utf-8-sig') as vpn_file:
    vpn_reader = csv.DictReader(vpn_file)
    for row in vpn_reader:
        VPN_RANGES.append(row['IP_Address'])

#== IP INFO Cache ==#
#Save memory by loading all known IP addresses and their country into memory. Avoid repeated calls to the API if the address has been seen before.
try :
    with open(CACHE_PATH, 'r') as ip_file:
        ip_cache = json.load(ip_file)
except:
    ip_cache = {}

""""*** FUNCTIONS ****"""
# === clear contents of the alert file so we don't receive duplicate emails. Reads the headers and then writes just those to the csv === #
def Clear_File():
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, 'r') as f:
            header = f.readline()
        with open(ALERT_FILE, 'w') as f:
            f.write(header)
        print(f"[INFO] cleared {ALERT_FILE} content but retained header.")

# # === Gets the current and previous timestamps and then uses that time range to run GAM login report === #
def Get_Users():
    # == GAM Run Statement == #
    #== An important NOTE GAM only takes UTC (PDT is UTC -7 hours) so for manually testing need to offset that time. The last and now variables already account for this
    # !!! Test GAM Command !!! #
    # with open("GAM_PATH, "w") as outfile:
    #     subprocess.run([
    #         GAM_CMD,
    #         "report", "login",
    #         "start", "2025-10-14T23:51:00Z",
    #         "end", "2025-10-14T22:56:00Z"
    #     ], stdout=outfile, stderr=subprocess.PIPE)

    # subprocess.run([
    #     GAM_CMD,
    #     "report", "login",
    #     "start", "2025-10-14T23:51:00Z",
    #     "end", "2025-10-14T22:56:00Z"
    # ])

    #Google does not write to the reporter for about 3 hours so include an offset of 3 hours and then search a 20 minute window
    offset_end = datetime.now(UTC) - timedelta(hours=3)
    offset_start = offset_end - timedelta(minutes=20)
    zulu_end = offset_end.isoformat(timespec='seconds').replace('+00:00', 'Z')
    zulu_start = offset_start.isoformat(timespec='seconds').replace('+00:00', 'Z')
    pdt_end = datetime.now() - timedelta(hours=3)
    pdt_start = pdt_end - timedelta(minutes=20)

    print(f"[INFO] Checking logins between {zulu_start}UTC and {zulu_end}UTC")
    print(f'PDT Times: start = {pdt_start} end = {pdt_end}')

    with open("PATH_TO_FILE", "w") as outfile:
        subprocess.run([
            GAM_CMD,
            "report", "login",
            "start", zulu_start,
            "end", zulu_end
        ], stdout=outfile, stderr=subprocess.PIPE)

# === Function to get users in the No CA OU === #
def No_CA():
    all_users = []
    header = None

    ou_paths = [
        "LIST OF NoCA OUs HERE"
    ]
    for ou in ou_paths:
        result = subprocess.run(
            [GAM_CMD, "print", "users", "query", f"orgUnitPath='{ou}'"], capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[Error] GAM Command Failed for {ou}")
            print(result.stderr)
            continue
        reader = csv.DictReader(io.StringIO(result.stdout)) #this takes the output of the GAM cmd - which outputs a file-like object - and allows you to parse through it as if it was a csv file while in memory rather than writing it to a file
        if not header:
            header = reader.fieldnames
        for row in reader:
            all_users.append(row)

    allowed_users = {row['primaryEmail'].lower() for row in all_users if 'primaryEmail' in row}
    return allowed_users

#== Get the country the user log in came from based off of IP Address by accessing IP INFO API ==#
def Get_Country(ip):
    if ip in ip_cache:
        return ip_cache[ip] # if that ip address was already searched then just return the country associated with that IP
    try:
        if ip.startswith(('192.','172.', '10.')):
            country = "Private"
        else:
            res = requests.get(f'https://ipinfo.io/{ip}?token={IPINFO_TOKEN}', timeout=5) #api call out to ipinfo which returns a country based on IP address
            country = res.json().get('country', 'Unknown')
    except Exception as e:
        print(f"[WARN] IP Lookup Failed for {ip}: {e}")
        country = "Unknown"
    ip_cache[ip] = country #updates IP cache with the current ipaddress : country key-value pair
    return country

# # == Function to translate country code to country name == #
def Country_Code_Translate(country):
    country_file = "PATH_TO_FILE" #I just pulled a known record of country codes and put that info in a csv. Unless new countries start popping up info shouldn't need to be updated
    country_lookup = {}
    with open(country_file, newline='', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            code = row['Code'].strip()
            name = row['Country'].strip()
            country_lookup[code] = name
        return country_lookup.get(country, country) #This is how .get works with dict (key, default) which essentially means if key exists in the dict return the value, otherwise return default. So in this case return the country value that was passed if the country value was not found as a key 

# # === Run the ip check for the country or VPN ip range == #
def VPN_Check(VPN_RANGES, ip):
    banned_subnets = [ipaddress.ip_network(range, False) for range in VPN_RANGES] #read in the subnets to the banned_subnets variable. (range, False) range is the address being read in and False is allowing it to be a subnet (/16, /24 etc) if it had been true it would error because true requires exact addresses and no masks
    student_ip = ipaddress.ip_address(ip)

    subnet_match = next((net for net in banned_subnets if student_ip in net), None) #this is the same as saying for net in banned_subnets if student_ip is in net return net and the next essentially is the same as get first match or None if no match

    if subnet_match:
        print(f'VPN Range Detected: {subnet_match}')
        return subnet_match
    else: 
        return None
    
#quick function to confirm the ip address pulled is a valid IP
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# === Check and report non-US logins or VPN Logins === #
def Unapproved_Logins():
    non_us_logins = []
    no_ca_users = No_CA() #function call to get No CA OU
    seen_this_run = set() #prevent duplicates
    seen_today = set()
    with open(ALERT_FILE, 'r', newline='') as check_file:
        reader = csv.DictReader(check_file)
        for row in reader:
            alert_email = row.get('actor.email')
            seen_today.add(alert_email)

    with open("PATH_TO_FILE",mode='r', newline='') as infile:
        try:
            reader = csv.DictReader(infile)
            rows = list(reader)
            print(f'[DEBUG] Rows parsed by csv.DictReader: {len(rows)}')
            for row in rows:
                #Pull the necessary info from temp logins
                login_type = row.get('name')
                if login_type != 'login_success':
                    continue
                #Check if they are already in ALERT_FILE and skip that user if that is the case
                email = row.get('actor.email')
                if email in seen_today:
                    continue
                ip = row.get('ipAddress')
                time_str = row.get('id.time')

                #if it pulls a blank for any of these its not a valid login report
                if not email or not ip or not time_str:
                    continue #NOTE continue moves to the next iteration of the for loop

                #find the country they logged in with Get_Country function (based on ip)
                country = Get_Country(ip)
                time.sleep(0.5)
                vpn_status = VPN_Check(VPN_RANGES, ip) #this is to see if their IP is associated with a VPN subnet
                print(vpn_status)

                #if they are in no_ca ignore them. Placed below VPN_Check to prevent VPN logins even if they are traveling overseas
                if email.lower() in no_ca_users:
                    continue

                #confirm this is a valid ip address
                if not isinstance(ip,str) or not is_valid_ip(ip):
                    print(f'[Warn] Invalid ip format: {ip}')
                    continue

                #if this username has been processed already - move on
                login_key = f"{email},{time_str}"
                if login_key in seen_this_run:
                    continue 
                seen_this_run.add(login_key) #add the processed user to the seen this run set to prevent duplicate processing
                
                #Read the values into a dictionary with the same header values they were pulled from. Allows for header control in the following csv
                login = {
                    'actor.email' : email,
                    'ipAddress' : ip,
                    'id.time' : time_str,
                    'country' : country,
                    'vpn' : str(vpn_status) if vpn_status else ''
                }

                #Check if its an unapproved country or if its a VPN login and add it to the non_us_login list
                if isinstance(login['country'], str) and login['country'] not in ['US', 'CA', 'MX','Private', 'Unknown'] :
                    login['country'] = Country_Code_Translate(login['country'])
                    non_us_logins.append(login)
                    print(f"[ALERT] Non-US login: {email} from {country} ({ip})")
                if vpn_status:
                    non_us_logins.append(login)
                    print(f'[ALERT] VPN Login detected: for {login["actor.email"]} at {ip}')
        except Exception as e:
            print(f'Error occurred: {e}')
    return non_us_logins

# # === Write all non-US logins to a csv file ===
def Unapproved_Login_Writer():
    #read in values of non_us_logins to look for duplicates
    existing = set()
    with open(ALERT_FILE, newline='') as check_file:
        reader = csv.DictReader(check_file)
        for row in reader:
            #row is a dict - existing is a set have to reconvert to a hashable object
            key = (row['actor.email'],row['ipAddress'], row['id.time'], row['country'], row['vpn'])
            existing.add(key)

    fieldnames = ['actor.email', 'ipAddress', 'id.time', 'country', 'vpn']
    logins = Unapproved_Logins() #gets the non_us_logins from Unapproved logins and carries it over to this function

    #check if a login is in existing. FIXME existing is a dict and logins are a list
    filtered_logins = []
    for login in logins:
        #login is a list - existing is a set
        key = (login['actor.email'], login['ipAddress'], login['id.time'], login['country'], login['vpn'])
        if key in existing:
            filtered_logins.append(login)

    if logins:
        print(f"[INFO] Logging {len(logins)} non-US logins to alert file.")
        new_file = not os.path.exists(ALERT_FILE)
        with open(ALERT_FILE, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames) #Fun NOTE for myself fieldnames are the headers/column names (depends on what you wann call it) - not sure why that confused me
            if new_file:
                writer.writeheader()
            writer.writerows(logins)
    return logins #return non_us_logins again to avoid calling Unapproved logins a second time. This is returned for UPN_List function

# # === Get their unique Google ID to create the URL ===#
def Get_ID(email):
    id_cmd = f'{GAM_CMD} info user {email} | findstr "Google Unique ID"'
    result = subprocess.run(id_cmd, shell=True, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "Google Unique ID" in line:
            return line.split(":", 1)[1].strip()
          
#== Splits a users email into Firstname Lastname which is the UPN 99% of the time ==#
def Get_UPN(email):
    username = email.split('@')[0]
    username = username.replace('.', ' ')
    name = username.title()

    return name

#== Get list of UPNs (full names) for each user to suspend so that the powershell script can suspend each one ==#
def UPN_List(non_us_logins):
    with open('PATH_TO_FILE', 'w', newline='') as UPN_File:
        fieldnames = ['UPN'] #AKA Column headers :^)
        writer = csv.DictWriter(UPN_File, fieldnames=fieldnames)
        writer.writeheader()
        for user in non_us_logins:
            user_upn = Get_UPN(user['actor.email'])
            writer.writerow({'UPN' : user_upn})
           
#=== Suspend User in AD. Calls a ps1 script that run the AD sided stuff === #
def Suspend_Users():
    subprocess.run([
        "powershell.exe", "-ExecutionPolicy", "Bypass",
        "-File", "PATH_TO_PS_FILE",
        "-username", admin_username,
        "-password", admin_password
    ])

#=== Function to get the parent recipeint list for each suspended student ===#
def Parent_Email(student_email):
    #Using sets will prevent duplicates so they are perfect for this use case - I just learned about sets :^)
    parent_emails = set()    
    with open(PARENT_EMAILS_SHEET, newline='', encoding='utf-8-sig') as parent_file:
        parent_reader = csv.DictReader(parent_file)
        for parent_row in parent_reader:
            student_Q_email = parent_row.get('Student Email Address')
            if student_email in student_Q_email.strip().lower():
                for field in [
                    'HH1 P1 Email Address', #qmlativs naming scheme for each households set of parents
                    'HH1 P2 Email Address',
                    'HH2 P1 Email Address',
                    'HH2 P2 Email Address',
                ]:
                    email = parent_row.get(field)
                    if email: #this will not append anything if there is not a parent email for instance a lot of students will not have anything in the hh2 p1 and p2 fields
                        parent_emails.add(email.strip())

    return list(parent_emails)

#Format time string to output a bit cleaner
def Time_Cleanup(time_str):
    datetime_object = datetime.fromisoformat(time_str)
    return datetime_object.strftime("%a, %b %d @ %I:%M %p")

#=== Send an email for any alerts === #
def Email_Message(logins):
    for log in logins:
        #email variables (pulled from Alert File by their header names)
        nus_email = log.get('actor.email')
        nus_ip = log.get('ipAddress')
        nus_time_str = log.get('id.time')
        nus_country = log.get('country')
        vpn = log.get('vpn')
        full_country = Country_Code_Translate(nus_country) #translate the country code to full country name
        id = Get_ID(nus_email)
        url = f"https://admin.google.com/ac/users/{id}"
        print(f'UPN is {Get_UPN(nus_email)}')

        #Email Contents
        if 'studentdomain.org' in nus_email: #if a student email, email to their parents email and only send report to network admins at EOD
            recipients = Parent_Email(nus_email)
            subject = f"(Important) district Google Account Suspended for {nus_email}"
            if vpn:
                email_body_html = f"""
                <html>
                <body>
                <p><strong>Student account has been suspended for logging in with a VPN.</strong></p>
                <p>
                    Hello,<br><br>

                    We received an alert that there was a succesful login for {nus_email} in a known IP address range associated with unapproved VPNs.<br><br>

                    In most cases, this is because the student themselves is utilizing a VPN application. Our district implements a security policy that prevents all logins to (District Here) Google accounts from unapproved VPNs.<br><br>
                    <strong> What is a VPN and Why It Matters</strong><br>
                    A VPN (Virtual Private Network) is a tool that allows users to hide their location and internet activity by routing their connection through private servers. VPNs can be used for privacy, but they are often used by students to get around our filters and access innapropriate or potentially dangerous websites.<br><br>
                    A VPN is only as trustworthy as its provider. Big-name VPNs such as NordVPN and Proton can be trusted to keep your data safe, but thousands of VPNs operate under the guise of being free, all while stealing your data that passes through their servers. If your student is utilizing one of these untrustworthy VPN providers, their data is at risk.<br><br>


                    <strong>Currently</strong>, your student's account is disabled. Since we are unable to email them directly, we are reaching out to you so that you may inquire if they are using a VPN. The VPN might be on their district device, a personal device or, their phone.<br>
                    <div style="margin-left: 20px;">
                    1) If you can confirm a VPN was used with their account, we can re-enable their account since this would confirm it was not a malicious login. Please ask them to remove the VPN or go to their building's tech office.<br><br>
                    </div>
                    <div style="margin-left: 20px;">
                    2) If a VPN is not being utilized by your student, please let us know so that we can investigate further and take necessary steps to secure the account.<br><br>
                    </div>
                    Please feel free to reach out with any questions.<br><br>
                </p>
                Sincerely,<br><br>
                Network Administrators
                </body>
                </html>
                """
            else:
                #Uses the function to convert country code to actual country name
                email_body_html = f"""
                <html>
                <body>
                <p><strong>Student account has been suspended for login activity outside of the US.</strong></p>
                <p>
                    Hello,<br><br>

                    We received an alert that there was a succesful login for {nus_email} from {full_country}.<br><br>

                    In most cases, this is because the student is utilizing a VPN application. Our district implements a security policy that prevents all logins to district Google accounts from outside North America.<br>
                    This often is also because the student is actually traveling outside of the country. If this is the case, please reply to this email and include the date they will return so we can modify their account settings. <br><br>
                    <strong> What is a VPN and Why It Matters</strong><br>
                    A VPN (Virtual Private Network) is a tool that allows users to hide their location and internet activity by routing their connection through private servers. VPNs can be used for privacy, but they are often used by students to get around our filters and access innapropriate or potentially dangerous websites.<br><br>
                    
                    A VPN is only as trustworthy as its provider. Big-name VPNs such as NordVPN and Proton can be trusted to keep your data safe, but thousands of VPNs operate under the guise of being free, all while stealing your data that passes through their servers. If your student is utilizing one of these untrustworthy VPN providers, their data is at risk.<br><br>

                    <strong>Currently</strong>, your student's account is disabled. Since we are unable to email them directly, we are reaching out to you so that you may inquire if they are using a VPN. The VPN might be on their district device, a personal device or, their phone.<br>
                    <div style="margin-left: 20px;">
                    1) If you can confirm a VPN was used with their account, we can re-enable their account since this would confirm it was not a malicious login.<br><br>
                    </div>
                    <div style="margin-left: 20px;">
                    2) If a VPN is not being utilized by your student, please let us know so that we can investigate further and take necessary steps to secure the account.<br><br>
                    </div>
                    Please feel free to reach out with any questions.<br>

                </p>
                Sincerely,<br><br>

                Network Administrators
                </body>
                </html>
                """

        else: #if it is a staff member send message to network admins
            recipients = ["address1", "address2"]#FIXME Deprecated in June
            subject = f"***Google Account Suspended for {nus_email}***"
            email_body_html = f"""
        <html>
        <body>
            <p><strong>USER ACCOUNT SUSPENDED.</strong></p>
            <ul>
                <li><strong>User Account: {nus_email}</li>
                <li><strong>Time: {Time_Cleanup(nus_time_str)}</li>
                <li><strong>IP Address: {nus_ip}</li>
                <li><strong>Country or IP Range: {full_country}</li>
            </ul>
            <p><strong>View User in Google Admin:</strong><p>
            <a href="{url}"><strong>{url}</strong></a></p>
        </body>
        </html>
        """
            
        recipient_str = ', '.join(recipients)
        print(f'Recipients for {nus_email} are {recipients}')
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = recipient_str
        message['Cc'] = 'ccaddress'
        message['Reply-To'] = 'reply addresses'
        message.attach(MIMEText(email_body_html, "html"))
        with smtplib.SMTP(smtp_server, smtp_port) as smtp:
            smtp.starttls()
            smtp.sendmail(sender_email, recipients, message.as_string())
        print(f"Sent email alert for {nus_email} to {recipients}")
        
if __name__ == '__main__':
    #== Function Calls ==#
    Get_Users()
    non_us_logins = Unapproved_Login_Writer() #login writer returns non_us_logins and writes them to the csv
    if non_us_logins: #needed a way to only run suspend_users() if there were non_us_logins
        UPN_List(non_us_logins)
        Suspend_Users()
        Email_Message(non_us_logins)

    #IP_Cache is destroyed when written to. Write to temp and then overwrite cache in a crash-safe way
    try:
        with open(TEMP_PATH, 'w') as f:
            print(f'Writing {len(ip_cache)} address mapping(s) to ip_cache.json')
            json.dump(ip_cache, f)
        os.replace(TEMP_PATH, CACHE_PATH)
    except Exception as e:
        print(f'Exception: failed to write to IP Cache: {e}')

    print(f'Finished running at {NOW}')

    #Clear_File()
    print(f"[INFO] Run complete. {len(non_us_logins)} new non-US logins.")