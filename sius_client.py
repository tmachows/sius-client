# -*- coding: utf-8 -*-

import time
import datetime
import requests
import logging
import win32api
import win32gui
import win32process
import wmi
import win32con
import threading
from tkinter import *


server_url = 'http://vps362165.ovh.net:8000'

user = {
    "username": "admin",
    "password": "adminpass1"
}
auth_token = None

apps = {}
current_app = None
is_event_active = False

c = wmi.WMI()

logging.basicConfig(format='[sius-client] %(levelname)s: %(message)s', level=logging.DEBUG)


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
                file_description = get_file_description(newExe)
                handle_current_app(file_description)
            except Exception as e:
                print(e)


def handle_current_app(app):
    global current_app
    global is_event_active
    if app != current_app.get() and app in apps and apps[app].get() is True:
        if is_event_active:
            send_finished_event(current_app.get())
        send_started_event(app)
        is_event_active = True
    if (app in apps and apps[app].get()) is False:
        if is_event_active and app != current_app.get():
            send_finished_event(current_app.get())
        is_event_active = False
    current_app.set(app)

def send_started_event(app):
    event_started_url = server_url + "/user/" + user["username"] + "/" + app + "/" # + "?format=json"
    current_time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    try:
        response = requests.post(event_started_url, json={"start_time": current_time}, 
                                 headers={"Authorization": "Token " + auth_token})
        check_status(response)
    except requests.exceptions.ConnectionError as conErr:
        logging.error("Connection error while sending start event: " + str(conErr))
        sys.exit(1)


def send_finished_event(app):
    event_finished_url = server_url + "/user/" + user["username"] + "/" + app + "/session/" # + "?format=json"
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


def gui_thread_function():
    root = Tk()
    setup_window(root)
    
    login_frame = Frame(root)
    apps_frame = Frame(root)

    login_frame.grid(row=0, column=0, sticky='news')
    apps_frame.grid(row=0, column=0, sticky='news')

    Label(login_frame, text="Username: ").grid(row=0, column=0, sticky='W')
    user_input = Entry(login_frame, bd=5)
    user_input.grid(row=0, column=1, sticky='W')
    Label(login_frame, text="Password: ").grid(row=1, column=0, sticky='W')
    pass_input = Entry(login_frame, bd=5, show="*")
    pass_input.grid(row=1, column=1, sticky='W')
    Button(login_frame, text='Login', command=lambda:log_in_and_change_frame(user_input, pass_input, apps_frame)).grid(row=2, column=0, sticky='W')

    login_frame.tkraise()
    root.mainloop()


def log_in_and_change_frame(user_input, pass_input, apps_frame):
    global auth_token
    global user

    user["username"] = user_input.get()
    user["password"] = pass_input.get()
    auth_token = login()
    predefined_apps = get_apps_from_server()

    setup_apps_frame(apps_frame, predefined_apps)
    apps_frame.tkraise()

    monitoring_thread = threading.Thread(target=monitoring_thread_function)
    monitoring_thread.start()


def setup_apps_frame(apps_frame, predefined_apps):
    global apps
    global current_app

    r = 0

    apps_header = Label(apps_frame, text="Apps to be tracked:").grid(row=r, column=0)
    r = r + 1

    for app in predefined_apps:
        app = app['app']
        apps[app] = BooleanVar()
        l = Checkbutton(apps_frame, text=app, variable=apps[app]).grid(row=r, column=0, sticky='W')
        r = r + 1

    current_app_label = Label(apps_frame, text="Currently running app:").grid(row=r, column=0)
    r = r + 1

    current_app = StringVar()
    current_app_label = Label(apps_frame, textvariable=current_app).grid(row=r, column=0)


def monitoring_thread_function():
    global active_app
    global active_app_text

    while True:  
        date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        active_app = win32gui.GetForegroundWindow()
        active_app_text = win32gui.GetWindowText(active_app)
        enum_handler(active_app, None)

        time.sleep(1)


if __name__ == "__main__":

    logging.info("Starting apps time monitoring...")

    gui_thread = threading.Thread(target=gui_thread_function)
    gui_thread.start()

    