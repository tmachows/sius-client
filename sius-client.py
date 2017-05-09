# -*- coding: utf-8 -*-

import psutil
import platform
import sys
import argparse
import time
import datetime
import threading
import requests
import logging


server_address = 'http://rosomak-server.herokuapp.com'
auth_token = None
station_id = None

logging.basicConfig(format='[RoSoMaK] %(levelname)s: %(message)s', level=logging.DEBUG)


def token_amp():
    """
    Returns request authentication token to put in request url.
    Version with '&' character (as subsequent parameter).
    """
    return "&station_token={}".format(auth_token)


def token_q():
    """
    Returns request authentication token to put in request url.
    Version with '?' character (as first parameter).
    """
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


def retrieve_conf_from_server():
    conf_url = server_address + "/latestconfiguration/" + station_id + "?format=json" + token_amp()
    retrieved_conf = {}
    try:
        response = requests.get(conf_url)
        check_status(response)
        if response.status_code == 200:
            retrieved_conf = response.json()
    except requests.exceptions.ConnectionError as conErr:
        logging.error("Connection error while retrieving configuration from server: " + str(conErr))
        sys.exit(1)
    return retrieved_conf


def retrieve_conf_from_system():
    retrieved_conf = {'machine': platform.machine(),
                      'os': platform.platform(),
                      'cpu': platform.processor(),
                      'cores': psutil.cpu_count(),
                      'ram_total': int(psutil.virtual_memory().total / (1024 * 1024))}
    return retrieved_conf


def equal_confs(conf, retrieved_conf):
    return equal_dicts(conf, retrieved_conf, ['id', 'station'])


def equal_dicts(d1, d2, ignore_keys):
    ignored = set(ignore_keys)
    for k1, v1 in d1.items():
        if k1 not in ignored and (k1 not in d2 or d2[k1] != v1):
            return False
    for k2, v2 in d2.items():
        if k2 not in ignored and k2 not in d1:
            return False
    return True


def send_new_configuration():
    logging.info("Sending configuration to server...")
    conf_url = server_address + "/latestconfiguration/" + station_id + "/" + token_q()
    try:
        response = requests.post(conf_url, json=configuration)
        check_status(response)
    except requests.exceptions.ConnectionError as conErr:
        logging.error(conErr)
        sys.exit(1)


def dynamic_data_io_thread():
    io_url = server_address + "/dynamicdataio/" + station_id + "/" + token_q()

    last_read_bytes = psutil.disk_io_counters()[3]
    last_write_bytes = psutil.disk_io_counters()[4]
    last_sent_bytes = psutil.net_io_counters()[0]
    last_recv_bytes = psutil.net_io_counters()[1]
    time.sleep(5)

    while True:
        dynamic_data_io = {}
        read_bytes = psutil.disk_io_counters()[3]
        dynamic_data_io['read_bytes'] = read_bytes - last_read_bytes
        last_read_bytes = read_bytes

        write_bytes = psutil.disk_io_counters()[4]
        dynamic_data_io['write_bytes'] = write_bytes - last_write_bytes
        last_write_bytes = write_bytes

        sent_bytes = psutil.net_io_counters()[0]
        dynamic_data_io['sent_bytes'] = sent_bytes - last_sent_bytes
        last_sent_bytes = sent_bytes

        recv_bytes = psutil.net_io_counters()[1]
        dynamic_data_io['recv_bytes'] = recv_bytes - last_recv_bytes
        last_recv_bytes = recv_bytes

        logging.debug("I/O data: " + str(dynamic_data_io))

        dynamic_data_io['date'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        try:
            response = requests.post(io_url, json=dynamic_data_io)
            check_status(response)
        except requests.exceptions.ConnectionError as conErr:
            logging.warning(conErr)
            pass
        time.sleep(5)


def users_processes_thread():
    users_url = server_address + "/user/" + str(station_id) + "/" + token_q()
    previous_data = {}
    find_users_with_processes(previous_data)

    time.sleep(5)

    while True:
        users_with_processes = find_users_with_processes(previous_data)

        users_with_processes['time'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        logging.debug(users_with_processes)

        logging.debug(previous_data)

        try:
            response = requests.post(users_url, json=users_with_processes)
            check_status(response)
        except requests.exceptions.ConnectionError as con_err:
            logging.warning(con_err)
            pass

        time.sleep(5)


def find_users_with_processes(previous_data):
    users_with_processes = {"users": []}
    users = [user.name for user in psutil.users()]
    for user in users:
        user_with_processes = find_user_processes(user, previous_data)
        users_with_processes['users'].append(user_with_processes)
    return users_with_processes


def find_user_processes(user, previous_data):
    user_with_processes = {"name": user, "list": []}

    for pid in psutil.pids():
        p = psutil.Process(pid)
        try:
            if p.username().split('\\').pop() == user:
                usr_time, sys_time = count_cpu_times(user, p, previous_data)
                process = {
                    "name": p.name(),
                    "cpu_percent": int(p.cpu_percent(interval=0.01) * 100 / psutil.cpu_count()),
                    "ram_percent": int(p.memory_percent() * 100),
                    "usr_time": usr_time,
                    "sys_time": sys_time
                }
                user_with_processes["list"].append(process)
        except (psutil.AccessDenied, psutil.NoSuchProcess) as process_exception:
            logging.debug("Process exception: ", str(process_exception))
            pass

    return user_with_processes


def count_cpu_times(user_name, process, previous_data):
    if user_name in previous_data:
        if process.pid in previous_data[user_name]:
            p = previous_data[user_name][process.pid]
            times = process.cpu_times()
            usr_time = int(times.user * 1000) - p['usr_time']
            sys_time = int(times.system * 1000) - p['sys_time']
            p['usr_time'] = int(times.user * 1000)
            p['sys_time'] = int(times.system * 1000)
            return usr_time, sys_time
    usr_time = int(process.cpu_times().user * 1000)
    sys_time = int(process.cpu_times().system * 1000)
    if user_name not in previous_data:
        previous_data[user_name] = {}
    previous_data[user_name][process.pid] = {'usr_time': usr_time, 'sys_time': sys_time}
    return int(process.cpu_times().user * 1000), int(process.cpu_times().system * 1000)


def retrieve_dynamic_data():
    data = {'cpu_consumed': int(psutil.cpu_percent()),
            'ram_consumed': int(psutil.virtual_memory().percent),
            'date': datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
    logging.debug("Dynamic data:" + str(data))
    return data


if __name__ == "__main__":

    parse_args()

    logging.info("Starting monitoring system...")

    logging.info("Retrieving system configuration...")

    retrieved_configuration = retrieve_conf_from_server()

    configuration = retrieve_conf_from_system()

    logging.debug("Retrieved configuration from system: " + str(configuration))
    logging.debug("Retrieved configuration from server: " + str(retrieved_configuration))

    if not equal_confs(configuration, retrieved_configuration):
        send_new_configuration()

    logging.info("Configuration successful. Entering dynamic data loop...")

    io_thread = threading.Thread(target=dynamic_data_io_thread)
    io_thread.start()

    users_thread = threading.Thread(target=users_processes_thread)
    users_thread.start()

    dyn_url = server_address + "/dynamicdata/" + str(station_id) + "/" + token_q()

    while True:
        dynamic_data = retrieve_dynamic_data()

        try:
            r = requests.post(dyn_url, json=dynamic_data)
            check_status(r)
        except requests.exceptions.ConnectionError as e:
            logging.warning(e)
            pass
        time.sleep(1)
