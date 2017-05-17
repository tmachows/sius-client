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


server_address = 'http://rosomak-server.herokuapp.com'
auth_token = None
station_id = None

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


def check_status(response):
    logging.debug("Response code: " + str(response.status_code))
    # logging.debug("Response content: " + str(response.json()))
    response.raise_for_status()


c = wmi.WMI()


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
                print(get_file_description(newExe))
            except Exception as e:
                print(e)
        print


if __name__ == "__main__":

    # parse_args()

    logging.info("Starting apps time monitoring...")

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