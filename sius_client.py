# -*- coding: utf-8 -*-

import argparse
import time
import datetime
import requests
import logging
import win32api
import win32gui
import win32process
import wmi
import win32con
import tkinter
import threading


server_url = 'http://79.137.72.95:8000'

user = {
    "username": "admin",
    "password": "adminpass1"
}
auth_token = None

apps = {"Firefox": False, 
        "Microsoft Visual Studio 2015": False,
        "Python": False}
current_app = None

c = wmi.WMI()

logging.basicConfig(format='[sius-client] %(levelname)s: %(message)s', level=logging.DEBUG)


def get_token_amp_url_param():
    return "&station_token={}".format(auth_token)


def get_token_query_url_param():
    return "?station_token={}".format(auth_token)


def parse_args():
    global auth_token
    global station_id
    parser = argparse.ArgumentParser()
    required_args = ["station_id", "auth_token"]
    for arg in required_args:
        parser.add_argument(arg)
    args = parser.parse_args()
    auth_token = args.auth_token
    station_id = args.station_id


def login():
    login_url = server_url + "/rest-auth/login/" # + "?format=json"
    try:
        response = requests.post(login_url, json=user)
        check_status(response)
        if response.status_code == 200:
            return response.json()['key']
    except requests.exceptions.ConnectionError as conErr:
        logging.error("Connection error while authenticating: " + str(conErr))
        sys.exit(1)


def get_apps_from_server():
    apps_url = server_url + "/user/" + user['username'] + "/" # + "?format=json"
    try:
        response = requests.get(apps_url)
        check_status(response)
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.ConnectionError as conErr:
        logging.error("Connection error while getting apps list: " + str(conErr))
        sys.exit(1)


def check_status(response):
    logging.debug("Response code: " + str(response.status_code))
    # logging.debug("Response content: " + str(response.json()))
    response.raise_for_status()


def get_app_path(hwnd):
    try:
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        for p in c.query('SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = %s' % str(pid)):
            exe = p.ExecutablePath
            break
    except:
        return None
    else:
        return exe


def get_app_name(hwnd):
    try:
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        for p in c.query('SELECT Name FROM Win32_Process WHERE ProcessId = %s' % str(pid)):
            exe = p.Name
            break
    except:
        return None
    else:
        return exe


def get_file_description(windows_exe):
    try:
        language, codepage = win32api.GetFileVersionInfo(windows_exe, '\\VarFileInfo\\Translation')[0]
        stringFileInfo = u'\\StringFileInfo\\%04X%04X\\%s' % (language, codepage, "FileDescription")
        description = win32api.GetFileVersionInfo(windows_exe, stringFileInfo)
    except:
        description = "unknown"

    return description


def enum_handler(hwnd, lParam):
    if win32gui.IsWindowVisible(hwnd):
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        if hwnd != 0 or pid != 0:
            try:
                hndl = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 0, pid)
                newExe = win32process.GetModuleFileNameEx(hndl, 0)
                current_app = get_file_description(newExe)
                handle_current_app(current_app)
            except Exception as e:
                print(e)


def handle_current_app(app):
    global current_app
    logging.debug("handle current app global: " + current_app.get())
    logging.debug("handle current app param: " + app)
    if app != current_app.get():
        if current_app.get() != "":
            send_finished_event(current_app.get())
        current_app.set(app)
        send_started_event(app)


def send_started_event(app):
    event_started_url = server_url + "/user/app/" + app + "/" # + "?format=json"
    current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    try:
        response = requests.post(event_started_url, json={"start_time": current_time}, 
                                 headers={"Authorization": "Token " + auth_token})
        check_status(response)
    except requests.exceptions.ConnectionError as conErr:
        logging.error("Connection error while sending start event: " + str(conErr))
        sys.exit(1)


def send_finished_event(app):
    event_finished_url = server_url + "/user/app/" + app + "/session/" # + "?format=json"
    current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    try:
        response = requests.delete(event_finished_url, json={"end_time": current_time}, 
                                 headers={"Authorization": "Token " + auth_token})
        check_status(response)
    except requests.exceptions.ConnectionError as conErr:
        logging.error("Connection error while sending finish event: " + str(conErr))
        sys.exit(1)


def setup_window(root):
    width = 300
    height = 200
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    x = screen_width - width - 20
    y = screen_height - height - 80

    root.geometry('%dx%d+%d+%d' % (width, height, x, y))

    root.wm_title("Apps time tracking")


def gui_thread():
    global apps
    global current_app

    top = tkinter.Tk()
    setup_window(top)
    r = 0

    apps_header = tkinter.Label(top, text="Choose apps to be tracked:").grid(row=r, column=0)
    r = r + 1

    for app in apps:
        apps[app] = tkinter.BooleanVar()
        l = tkinter.Checkbutton(top, text=app, variable=apps[app]).grid(row=r, column=0, sticky='W')
        r = r + 1

    current_app_label = tkinter.Label(top, text="Currently running app:").grid(row=r, column=0)
    r = r + 1

    current_app = tkinter.StringVar()
    current_app_label = tkinter.Label(top, textvariable=current_app).grid(row=r, column=0)

    top.mainloop()


if __name__ == "__main__":

    # parse_args()

    logging.info("Starting apps time monitoring...")
    
    auth_token = login()

    apps = get_apps_from_server()

    logging.info("Auth token: " + str(auth_token))
    logging.info("Apps: " + str(apps))

    _gui_thread = threading.Thread(target=gui_thread)
    _gui_thread.start()

    while True:  
        date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        active_app = win32gui.GetForegroundWindow()
        active_app_text = win32gui.GetWindowText(active_app)
        enum_handler(active_app, None)

        # win32gui.EnumWindows(enum_handler, None)
       

        #try:
         #   r = requests.post(dyn_url, json=dynamic_data)
          #  check_status(r)
        #except requests.exceptions.ConnectionError as e:
         #   logging.warning(e)
          #  pass

        time.sleep(1)