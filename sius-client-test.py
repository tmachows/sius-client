# -*- coding: utf-8 -*-

import unittest

from leaf.rosomak import *


class TestRosomakFunctions(unittest.TestCase):
    def test_local_conf(self):
        configuration = retrieve_conf_from_system()
        self.assertIsNotNone(configuration)
        self.assertEqual(len(configuration), 5)
        self.assertIsInstance(configuration['machine'], str)
        self.assertIsInstance(configuration['os'], str)
        self.assertIsInstance(configuration['cpu'], str)
        self.assertIsInstance(configuration['cores'], int)
        self.assertIsInstance(configuration['ram_total'], int)

    def test_compare_confs_true(self):
        conf1 = {'machine': 'AMD64', 'os': 'Linux', 'cpu': 'Intel', 'cores': 2, 'ram_total': 4000000}
        conf2 = {'machine': 'AMD64', 'os': 'Linux', 'cpu': 'Intel', 'cores': 2, 'ram_total': 4000000}
        self.assertTrue(equal_confs(conf1, conf2))

    def test_compare_confs_false(self):
        conf1 = {'machine': 'AMD64', 'os': 'Linux', 'cpu': 'Intel', 'cores': 2, 'ram_total': 4000000}
        conf2 = {'machine': 'IA64', 'os': 'Windows', 'cpu': 'Intel', 'cores': 2, 'ram_total': 6000000}
        self.assertFalse(equal_confs(conf1, conf2))

    def test_dynamic_data_retrieve(self):
        dynamic_data = retrieve_dynamic_data()
        self.assertIsNotNone(dynamic_data)
        self.assertEqual(len(dynamic_data), 3)
        self.assertIsInstance(dynamic_data['cpu_consumed'], int)
        self.assertIsInstance(dynamic_data['ram_consumed'], int)
        self.assertTrue(0 <= dynamic_data['cpu_consumed'] <= 100)
        self.assertTrue(0 <= dynamic_data['ram_consumed'] <= 100)

    def test_finding_user_processes_without_previous_data(self):
        user = psutil.users().pop().name
        user_with_processes = find_user_processes(user, {})
        self.assertIsNotNone(user_with_processes)
        self.assertTrue(all(key in user_with_processes for key in ['name', 'list']))
        self.assertEqual(user_with_processes['name'], user)
        for process in user_with_processes['list']:
            self.assertTrue(
                all(key in process for key in ['name', 'cpu_percent', 'ram_percent', 'usr_time', 'sys_time'])
            )

    def test_finding_user_processes_with_previous_data(self):
        user = psutil.users().pop().name
        previous_data = {}
        find_user_processes(user, previous_data)
        user_with_processes = find_user_processes(user, previous_data)
        self.assertIsNotNone(user_with_processes)
        self.assertTrue(all(key in user_with_processes for key in ['name', 'list']))
        self.assertEqual(user_with_processes['name'], user)
        for process in user_with_processes['list']:
            self.assertTrue(
                all(key in process for key in ['name', 'cpu_percent', 'ram_percent', 'usr_time', 'sys_time'])
            )

    def test_finding_users_with_processes(self):
        users_with_processes = find_users_with_processes({})
        self.assertIsNotNone(users_with_processes)
        self.assertTrue('users' in users_with_processes)
        self.assertTrue(isinstance(users_with_processes['users'], list))
        for user in users_with_processes['users']:
            self.assertTrue(all(key in user for key in ['name', 'list']))


suite = unittest.TestLoader().loadTestsFromTestCase(TestRosomakFunctions)
unittest.TextTestRunner(verbosity=2).run(suite)
