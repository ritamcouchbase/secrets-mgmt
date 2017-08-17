from threading import Thread, Event
from couchbase.bucket import Bucket
from upgrade.upgrade_tests import UpgradeTests
from testmemcached import TestMemcachedClient
from rbacmem import RbacTestMemcached
from rbacmem import dataRoles
from membase.api.rest_client import RestConnection
from security.rbac_base import RbacBase
from security.rbacmain import rbacmain
import urllib
from couchbase_helper.documentgenerator import BlobGenerator
from couchbase.n1ql import N1QLQuery
from testmemcached import TestSDK


class rbac_upgrade(UpgradeTests):

    def setUp(self):
        super(rbac_upgrade, self).setUp()
        self.host_ip = []
        for server in self.servers:
            self.host_ip.append(server.ip)
        self.upgrade_version = self.input.param('upgrade_version','5.0.0-3366')
        self.pre_upgrade_user = ''
        self.pre_upgrade_user_role = ''
        self.post_upgrade_user = ''
        self.post_upgrade_user_role = ''
        self.num_items = self.input.param('num_items',10000)

    def tearDown(self):
        super(rbac_upgrade, self).tearDown()

    def _return_actions(self, permission_set):
        permission_set = dataRoles()._return_permission_set(permission_set)
        action_list = permission_set['permissionSet']
        return action_list.split(",")

    def enable_ldap(self):
        rest = RestConnection(self.master)
        api = rest.baseUrl + 'settings/saslauthdAuth'
        params = urllib.urlencode({"enabled": 'true', "admins": [], "roAdmins": []})
        status, content, header = rest._http_request(api, 'POST', params)

    def check_roles(self, expected, actual):
        final_result = True
        for temp_role in expected:
            result = False
            for temp1 in actual['users']:
                if temp1['id'] == temp_role['id']:
                    if 'admin' not in temp_role.keys():
                        if (temp1['roles'][0]['bucket_name'] == '*'):
                            bucket_name = '*'
                        else:
                            bucket_name = temp_role['bucket']
                        if temp1['roles'][0]['bucket_name'] == bucket_name and temp1['roles'][0]['role'] == \
                                temp_role['action_list']:
                            result = True
                    else:
                        if temp1['roles'][0]['role'] == temp_role['roles']:
                            result = True
                if final_result == True and result == True:
                    final_result = True
            print "Results for user - {0} is {1}  ----".format(temp_role['id'], result)
        self.assertTrue(final_result, "Error after upgrade for ")

    def setup_4_5_users(self):
        rest = RestConnection(self.master)
        self.enable_ldap()

        self.pre_upgrade_user = [{'id': 'pre_admin', 'name': 'pre_admin', 'password': 'p@ssword'}, \
                                 {'id': 'pre_cluster_admin', 'name': 'pre_cluster_admin', 'password': 'p@ssword'}, \
                                 {'id': 'pre_bucket_admin_all', 'name': 'pre_bucket_admin_all', 'password': 'p@ssword'}, \
                                 {'id': 'pre_bucket_admin_bucket_01', 'name': 'pre_bucket_admin_bucket_01',
                                  'password': 'p@ssword'}, \
                                 {'id': 'pre_bucket_admin_bucket_02', 'name': 'pre_bucket_admin_bucket_02',
                                  'password': 'p@ssword'}, \
                                 {'id': 'pre_view_admin_all', 'name': 'pre_view_admin_all', 'password': 'p@ssword'}, \
                                 {'id': 'pre_view_admin_bucket', 'name': 'pre_view_admin_bucket',
                                  'password': 'p@ssword'}, \
                                 {'id': 'pre_replication_admin', 'name': 'pre_replication_admin',
                                  'password': 'p@ssword'}, \
                                 {'id': 'pre_readonly_admin', 'name': 'pre_readonly_admin', 'password': 'p@ssword'}, \
                                 {'id': 'bucket_admin_01', 'name': 'bucket_admin_01', 'password': 'p@ssword'}, \
                                 {'id': 'bucket_admin_02', 'name': 'bucket_admin_02', 'password': 'p@ssword'}, \
                                 {'id': 'bucket_admin_03', 'name': 'bucket_admin_03', 'password': 'p@ssword'}, \
                                 {'id': 'bucket_admin_04', 'name': 'bucket_admin_04', 'password': 'p@ssword'}, \
                                 {'id': 'bucket_admin_05', 'name': 'bucket_admin_05', 'password': 'p@ssword'}]

        RbacBase().create_user_source(self.pre_upgrade_user, 'ldap', self.master)

        self.pre_upgrade_user_role = [{'id': 'pre_admin', 'name': 'pre_admin', 'roles': 'admin',
                                       'action_list': 'admin', 'bucket': 'beforeupgadesasl', 'admin': 'yes'}, \
                                      {'id': 'pre_cluster_admin', 'name': 'pre_cluster_admin', 'roles': 'cluster_admin',
                                       'action_list': 'cluster_admin', 'bucket': 'beforeupgadesasl', 'admin': 'yes'}, \
                                      {'id': 'pre_bucket_admin_all', 'name': 'pre_bucket_admin_all',
                                       'roles': 'bucket_admin[*]',
                                       'action_list': 'bucket_admin', 'bucket': 'beforeupgadesimple'}, \
                                      {'id': 'pre_bucket_admin_bucket_01', 'name': 'pre_bucket_admin_bucket_01',
                                       'roles': 'bucket_admin[beforeupgadesimple]', 'action_list': 'bucket_admin',
                                       'bucket': 'beforeupgadesimple'}, \
                                      {'id': 'pre_bucket_admin_bucket_02', 'name': 'pre_bucket_admin_bucket_02',
                                       'roles': 'bucket_admin[beforeupgadesasl]', 'action_list': 'bucket_admin',
                                       'bucket': 'beforeupgadesasl'}, \
                                      {'id': 'pre_view_admin_all', 'name': 'pre_view_admin_all',
                                       'roles': 'views_admin[*]',
                                       'action_list': 'views_admin', 'bucket': 'beforeupgadesasl'}, \
                                      {'id': 'pre_view_admin_bucket', 'name': 'pre_view_admin_bucket',
                                       'roles': 'views_admin[beforeupgadesimple]',
                                       'action_list': 'views_admin', 'bucket': 'beforeupgadesimple'}, \
                                      {'id': 'pre_replication_admin', 'name': 'pre_replication_admin',
                                       'roles': 'replication_admin',
                                       'action_list': 'replication_admin', 'bucket': 'beforeupgadesimple', 'admin': 'yes'}, \
                                      {'id': 'pre_readonly_admin', 'name': 'pre_readonly_admin', 'roles': 'ro_admin',
                                       'action_list': 'readonly', 'bucket': 'beforeupgadesimple', 'admin': 'yes'}, \
                                      {'id': 'bucket_admin_01', 'name': 'bucket_admin_01',
                                       'roles': 'bucket_admin[beforeupgadesimple]',
                                       'action_list': 'bucket_admin', 'bucket': 'beforeupgadesimple'}, \
                                      {'id': 'bucket_admin_02', 'name': 'bucket_admin_02',
                                       'roles': 'bucket_admin[beforeupgadesasl]',
                                       'action_list': 'bucket_admin', 'bucket': 'beforeupgadesasl'}, \
                                      {'id': 'bucket_admin_03', 'name': 'bucket_admin_03',
                                       'roles': 'bucket_admin[beforeupgadesasl]',
                                       'action_list': 'bucket_admin', 'bucket': 'beforeupgadesasl'}, \
                                      {'id': 'bucket_admin_04', 'name': 'bucket_admin_04',
                                       'roles': 'bucket_admin[beforeupgadesimple]',
                                       'action_list': 'bucket_admin', 'bucket': 'beforeupgadesimple'}, \
                                      {'id': 'bucket_admin_05', 'name': 'bucket_admin_05',
                                       'roles': 'bucket_admin[beforeupgadesimple]',
                                       'action_list': 'bucket_admin', 'bucket': 'beforeupgadesimple'}]

        RbacBase().add_user_role(self.pre_upgrade_user_role, RestConnection(self.master), 'ldap')

    def change_role_pre_upg_data(self):

        change_role_pre_upg_user = [
            {'id': 'bucket_admin_01', 'name': 'bucket_admin_01', 'password': 'p@ssword'}, \
            {'id': 'bucket_admin_02', 'name': 'bucket_admin_02', 'password': 'p@ssword'}, \
            {'id': 'bucket_admin_03', 'name': 'bucket_admin_03', 'password': 'p@ssword'}, \
            {'id': 'bucket_admin_04', 'name': 'bucket_admin_04', 'password': 'p@ssword'}, \
            {'id': 'bucket_admin_05', 'name': 'bucket_admin_05', 'password': 'p@ssword'}]

        change_role_pre_upgrade_data = [
            {'id': 'bucket_admin_01', 'name': 'bucket_admin_01', 'roles': 'data_reader[afterupgrade01]',
             'action_list': 'data_reader', 'bucket': 'afterupgrade01'}, \
            {'id': 'bucket_admin_02', 'name': 'bucket_admin_02', 'roles': 'data_writer[afterupgrade01]',
             'action_list': 'data_writer', 'bucket': 'afterupgrade01'}, \
            {'id': 'bucket_admin_03', 'name': 'bucket_admin_03', 'roles': 'data_dcp_reader[afterupgrade01]',
             'action_list': 'data_dcp_reader', 'bucket': 'afterupgrade01'}, \
            {'id': 'bucket_admin_04', 'name': 'bucket_admin_04', 'roles': 'data_monitoring[afterupgrade01]',
             'action_list': 'data_monitoring', 'bucket': 'afterupgrade01'}, \
            {'id': 'bucket_admin_05', 'name': 'bucket_admin_05', 'roles': 'data_backup[afterupgrade01]',
             'action_list': 'data_backup', 'bucket': 'afterupgrade01'}]

        RbacBase().add_user_role(change_role_pre_upgrade_data, RestConnection(self.master), 'ldap')

        return change_role_pre_upg_user, change_role_pre_upgrade_data

    def upgrade_pass_old_bucket(self):

        change_role_pre_upg_user = [
            {'id': 'beforeupgadesasl', 'name': 'beforeupgadesasl', 'password': 'p@ssword'}, \
            {'id': 'beforeupgadesimple', 'name': 'beforeupgadesimple', 'password': 'p@ssword'}]

        change_role_pre_upgrade_data = [
            {'id': 'beforeupgadesasl', 'name': 'beforeupgadesasl', 'roles': 'bucket_full_access[beforeupgadesasl]',
             'action_list': 'bucket_full_access', 'bucket': 'beforeupgadesasl'}, \
            {'id': 'beforeupgadesimple', 'name': 'beforeupgadesimple', 'roles': 'bucket_full_access[beforeupgadesimple]',
             'action_list': 'bucket_full_access', 'bucket': 'beforeupgadesimple'}]

        if self.initial_version[0:5] != '3.1.5':
            change_role_pre_upg_user.append( {'id': 'travel-sample', 'name': 'travel-sample', 'password': 'p@ssword'} )
            change_role_pre_upgrade_data.append({'id': 'travel-sample', 'name': 'travel-sample', 'roles': 'bucket_full_access[travel-sample]',
             'action_list': 'bucket_full_access', 'bucket': 'travel-sample'})

        for i in range(0,len(change_role_pre_upg_user)):
            payload = "name=" + change_role_pre_upgrade_data[i]['id'] + "&roles=" + change_role_pre_upgrade_data[i]['roles'] + "&password=" + change_role_pre_upg_user[i]['password']
            RestConnection(self.master).add_set_builtin_user(change_role_pre_upgrade_data[i]['id'],payload)

        return change_role_pre_upg_user, change_role_pre_upgrade_data

    def post_upgrade_new_users_new_bucket(self):
        rest = RestConnection(self.master)
        self.enable_ldap()

        self.post_upgrade_user = [{'id': 'data_reader', 'name': 'data_reader', 'password': 'p@ssword'}, \
                                  {'id': 'data_writer', 'name': 'data_writer', 'password': 'p@ssword'}, \
                                  {'id': 'data_dcp_reader', 'name': 'data_dcp_reader', 'password': 'p@ssword'}, \
                                  {'id': 'data_monitoring', 'name': 'data_monitoring', 'password': 'p@ssword'}, \
                                  {'id': 'data_reader_bucket', 'name': 'data_reader_bucket', 'password': 'p@ssword'}, \
                                  {'id': 'data_writer_bucket', 'name': 'data_writer_bucket', 'password': 'p@ssword'}, \
                                  {'id': 'data_dcp_reader_bucket', 'name': 'data_dcp_reader_bucket',
                                   'password': 'p@ssword'}, \
                                  {'id': 'data_monitoring_bucket', 'name': 'data_monitoring_bucket',
                                   'password': 'p@ssword'}, \
                                  {'id': 'post_admin', 'name': 'post_admin', 'password': 'p@ssword'}, \
                                  {'id': 'post_cluster_admin', 'name': 'post_cluster_admin', 'password': 'p@ssword'}, \
                                  {'id': 'post_bucket_admin_all', 'name': 'post_bucket_admin_all',
                                   'password': 'p@ssword'}, \
                                  {'id': 'post_bucket_admin_bucket_01', 'name': 'post_bucket_admin_bucket_01',
                                   'password': 'p@ssword'}, \
                                  {'id': 'post_bucket_admin_bucket_02', 'name': 'post_bucket_admin_bucket_02',
                                   'password': 'p@ssword'}, \
                                  {'id': 'post_view_admin_all', 'name': 'post_view_admin_all', 'password': 'p@ssword'}, \
                                  {'id': 'post_view_admin_bucket', 'name': 'post_view_admin_bucket',
                                   'password': 'p@ssword'}, \
                                  {'id': 'post_replication_admin', 'name': 'post_replication_admin',
                                   'password': 'p@ssword'}, \
                                  {'id': 'post_readonly_admin', 'name': 'post_readonly_admin', 'password': 'p@ssword'}, \
                                  {'id': 'afterupgrade01', 'name': 'afterupgrade01', 'password': 'p@ssword'}, \
                                  {'id': 'afterupgrade02', 'name': 'afterupgrade02', 'password': 'p@ssword'}, \
                                  ]

        RbacBase().create_user_source(self.post_upgrade_user, 'builtin', self.master)

        self.post_upgrade_user_role = [{'id': 'post_admin', 'name': 'post_admin', 'roles': 'admin',
                                        'action_list': 'admin', 'bucket': 'afterupgrade01', 'admin': 'yes'}, \
                                       {'id': 'post_cluster_admin', 'name': 'post_cluster_admin',
                                        'roles': 'cluster_admin',
                                        'action_list': 'cluster_admin', 'bucket': 'afterupgrade02', 'admin': 'yes'}, \
                                       {'id': 'post_bucket_admin_all', 'name': 'post_bucket_admin_all',
                                        'roles': 'bucket_admin[*]',
                                        'action_list': 'bucket_admin', 'bucket': 'afterupgrade01'}, \
                                       {'id': 'post_bucket_admin_bucket_01', 'name': 'post_bucket_admin_bucket_01',
                                        'roles': 'bucket_admin[afterupgrade01]', 'action_list': 'bucket_admin',
                                        'bucket': 'afterupgrade01'}, \
                                       {'id': 'post_bucket_admin_bucket_02', 'name': 'post_bucket_admin_bucket_02',
                                        'roles': 'bucket_admin[afterupgrade02]', 'action_list': 'bucket_admin',
                                        'bucket': 'afterupgrade02'}, \
                                       {'id': 'post_view_admin_all', 'name': 'post_view_admin_all',
                                        'roles': 'views_admin[*]',
                                        'action_list': 'views_admin', 'bucket': 'afterupgrade01'}, \
                                       {'id': 'post_view_admin_bucket', 'name': 'post_view_admin_bucket',
                                        'roles': 'views_admin[afterupgrade02]',
                                        'action_list': 'views_admin', 'bucket': 'afterupgrade02'}, \
                                       {'id': 'post_replication_admin', 'name': 'post_replication_admin',
                                        'roles': 'replication_admin',
                                        'action_list': 'replication_admin', 'bucket': 'afterupgrade02', 'admin': 'yes'}, \
                                       {'id': 'post_readonly_admin', 'name': 'post_readonly_admin', 'roles': 'ro_admin',
                                        'action_list': 'readonly', 'bucket': 'afterupgrade02', 'admin': 'yes'}, \
 \
                                       {'id': 'data_reader', 'name': 'data_reader', 'roles': 'data_reader[*]',
                                        'action_list': 'data_reader', 'bucket': 'afterupgrade01'}, \
                                       {'id': 'data_writer', 'name': 'data_writer', 'roles': 'data_writer[*]',
                                        'action_list': 'data_writer', 'bucket': 'afterupgrade01'}, \
                                       {'id': 'data_dcp_reader', 'name': 'data_dcp_reader',
                                        'roles': 'data_dcp_reader[*]',
                                        'action_list': 'data_dcp_reader', 'bucket': 'afterupgrade01'}, \
                                       {'id': 'data_monitoring', 'name': 'data_monitoring',
                                        'roles': 'data_monitoring[*]',
                                        'action_list': 'data_monitoring', 'bucket': 'afterupgrade01'}, \
                                       {'id': 'data_reader_bucket', 'name': 'data_reader_bucket',
                                        'roles': 'data_reader[afterupgrade02]',
                                        'action_list': 'data_reader', 'bucket': 'afterupgrade02'}, \
                                       {'id': 'data_writer_bucket', 'name': 'data_writer_bucket',
                                        'roles': 'data_writer[afterupgrade02]',
                                        'action_list': 'data_writer', 'bucket': 'afterupgrade02'}, \
                                       {'id': 'data_dcp_reader_bucket', 'name': 'data_dcp_reader_bucket',
                                        'roles': 'data_dcp_reader[afterupgrade02]',
                                        'action_list': 'data_dcp_reader', 'bucket': 'afterupgrade02'}, \
                                       {'id': 'afterupgrade02', 'name': 'afterupgrade02',
                                        'roles': 'bucket_full_access[afterupgrade02]',
                                        'action_list': 'bucket_full_access', 'bucket': 'afterupgrade02'}, \
                                       {'id': 'afterupgrade01', 'name': 'afterupgrade01',
                                        'roles': 'bucket_full_access[afterupgrade01]',
                                        'action_list': 'bucket_full_access', 'bucket': 'afterupgrade01'}, \
                                       {'id': 'data_monitoring_bucket', 'name': 'data_monitoring_bucket',
                                        'roles': 'data_monitoring[afterupgrade02]',
                                        'action_list': 'data_monitoring', 'bucket': 'afterupgrade02'}
                                       ]

        RbacBase().add_user_role(self.post_upgrade_user_role, RestConnection(self.master), 'builtin')
        #for i in range(0,len(self.post_upgrade_user_role)):
        #    payload = "name=" + self.post_upgrade_user_role[i]['id'] + "&roles=" + self.post_upgrade_user_role[i]['roles'] + "&password=p@ssword"
        #    RestConnection(self.master).add_set_builtin_user(self.post_upgrade_user_role[i]['id'],payload)

    def change_pass_new_user(self):
        rest = RestConnection(self.master)
        for user in self.post_upgrade_user:
            rest.change_password_builtin_user(user['id'], 'password')

        for i in range(0, len(self.post_upgrade_user)):
            self.post_upgrade_user[i]['password'] = 'password'

    def test_memcached_connection(self, master_ip, user_list, role_list):
        for user in user_list:
            for temp_user in role_list:
                if str(temp_user['id']) in str(user['id']):
                    user_action = temp_user['action_list']
                    bucket_name = temp_user['bucket']
            action_list = self._return_actions(user_action)
            print "-------- Action List - {0} -- and user is {1}".format(action_list,user['id'])
            sdk_conn, result = TestSDK().connection(self.master.ip, bucket_name, user['id'], user['password'])
            for action in action_list:
                temp_action = action.split("!")
                if (result):
                    self.sleep(1)
                    result_action = None
                    if temp_action[0] == 'write':
                        result_action = TestSDK().write_data(sdk_conn)
                    elif temp_action[0] == 'read':
                        result_action = TestSDK().get_xattr(self.master.ip, sdk_conn, bucket_name)
                    elif temp_action[0] == 'WriteXattr':
                        result_action = TestSDK().set_xattr(sdk_conn)
                    elif temp_action[0] == 'ReadXattr':
                        result_action = TestSDK().get_xattr(self.master.ip, sdk_conn, bucket_name)
                    elif temp_action[0] == 'statsRead':
                        result_action = temp_action[1]
                    elif temp_action[0] == 'ReadMeta':
                        result_action = temp_action[1]
                    elif temp_action[0] == 'WriteMeta':
                        result_action = temp_action[1]
                    #self.log.info("Result of action - {0} is {1}".format(action, result_action))                    '''
                    if temp_action[1] == str(result_action):
                        self.assertTrue(True)
                    else:
                        self.log.info("Result of action - {0} is {1} -- {2}".format(action, result_action, temp_action[1]))
                        self.assertFalse(True)
                    
    def createBulkDocuments(self,bucket,password=None,start_num=0,end_num=10000,input_key='demo_key'):
        if password is not None:
            result, client = self._sdk_connection(bucket, host_ip=self.host_ip, password=password)
        else:
            result, client = self._sdk_connection(bucket, host_ip=self.host_ip)
        print client
        key1 = 'demo_key'
        value1 = {
          "name":"demo_value",
          "lastname":'lastname',
          "areapin":'',
          "preference":'veg',
          "type":''
        }
        for x in range (start_num, end_num):
            value = value1.copy()
            key = input_key
            key = key + str(x)
            for key1 in value:
                if value[key1] == 'type' and x % 2 == 0:
                    value['type'] = 'odd'
                else:
                    value['type'] = 'even'
                value[key1] = value[key1] + str(x)
            value['id'] = str(x)
            result = client.upsert(key, value)
        print "Finished uploading data"

    def execute_query(self, query=None, ddl=None, bucket='default', password=None, iteration=100):
        try:
            if password is not None:
                result, client = self._sdk_connection(bucket, host_ip=self.host_ip, password=password)
            else:
                result, client = self._sdk_connection(bucket, host_ip=self.host_ip)
            print client
            temp = []
            if ddl is not None:
                create_index_1 = 'create index simple_name_' + bucket + " on " + bucket + "(name)"
                create_index_2 = 'create index simple_type_' + bucket + " on " + bucket + "(type)"
                client.n1ql_query(create_index_1).execute()
                client.n1ql_query(create_index_2).execute()
                return
            if query is None:
                for i in range(0,iteration):
                    if i % 2 == 0:
                        test_query = 'select name from ' + bucket + ' where name is not NULL'
                    else:
                        test_query = 'select type from ' + bucket + ' where type is not NULL'
                    rs = client.n1ql_query(N1QLQuery(test_query))
                    for r in rs:
                        temp.append(r)
                        temp = []
            else:
                for i in range(0, iteration):
                    rs = client.n1ql_query(N1QLQuery(query))
                    for r in rs:
                        temp.append(r)
                        temp = []
                print "Finished Querying"
        except Exception, ex:
            print "Exception from execute query"
            print ex

    def _sdk_connection(self, bucket='default', host_ip=None, password=None):
        self.sleep(30)
        result = False
        host_ip = ','.join(host_ip)
        connection_string = 'couchbase://' + host_ip + '/' + bucket
        print connection_string
        try:
            if password is not None:
                cb = Bucket(connection_string, password=password)
            else:
                cb = Bucket(connection_string)
            if cb is not None:
                result = True
                return result, cb
        except Exception, ex:
            print "Exception from connection"
            print ex
            return result

    def pre_upgrade(self, offline=None):
        thread_list = []
        rest = RestConnection(self.master)
        rest.create_bucket(bucket='beforeupgadesasl', ramQuotaMB=100, authType='sasl', saslPassword='p@ssword')
        rest.create_bucket(bucket='beforeupgadesimple', ramQuotaMB=100, proxyPort=11212)
        self.create_ddocs_and_views()
        rest.set_indexer_storage_mode(storageMode="memory_optimized")


        create_docs_simple = Thread(name='create_docs_simple_bucket', target=self.createBulkDocuments, args=('beforeupgadesimple',None, 1, self.num_items))
        create_docs_sasl = Thread(name='create_docs_sasl_bucket', target=self.createBulkDocuments, args=('beforeupgadesasl', 'p@ssword', 1, self.num_items))
        thread_list.append(create_docs_simple)
        thread_list.append(create_docs_sasl)

        self.log.info ("Intial -version is ----------{0}".format(self.initial_version[0:5]))
        if self.initial_version[0:5] != '3.1.5':
            rest.load_sample("travel-sample")
            self.execute_query(query='CREATE INDEX simple_name ON beforeupgadesimple(name)', ddl='Yes',
                               bucket='beforeupgadesimple')
            self.execute_query(query='CREATE INDEX sasl_name ON beforeupgadesasl(name)', ddl='Yes',
                               bucket='beforeupgadesasl', password='p@ssword')

            query_docs_simple = Thread(name='query_docs_simple_bucket', target=self.execute_query, args=(None, None, 'beforeupgadesimple', None,))
            query_docs_sasl = Thread(name='query_docs_sasl_bucket', target=self.execute_query,
                                                args=(None, None, 'beforeupgadesasl', 'p@ssword', ))

            thread_list.append(query_docs_simple)
            thread_list.append(query_docs_sasl)


        for thread in thread_list:
            thread.start()

        if offline == True:
            for thread in thread_list:
                thread.join()

    def setup_4_1_settings(self):
        rest = RestConnection(self.master)
        self._setupLDAPAuth(rest, self.authRole, self.authState, self.fullAdmin, self.ROAdmin)

    def post_upgrade_buckets(self):
        rest = RestConnection(self.master)
        rest.create_bucket(bucket='afterupgrade01', ramQuotaMB=100, lww=True)
        rest.create_bucket(bucket='afterupgrade02', ramQuotaMB=100, lww=True)

    def check_sdk_connection_post_upgrade(self, pass_updated=None, online=None):
        sdk_user_check = [
            {'id': 'afterupgrade01', 'name': 'afterupgrade01', 'password': 'p@ssword', "bucket_name":'afterupgrade01'}, \
            {'id': 'afterupgrade01', 'name': 'afterupgrade02', 'password': 'p@ssword', "bucket_name":'afterupgrade02'}, \
            {'id': 'beforeupgadesasl', 'name': 'beforeupgadesasl', 'password': 'p@ssword', "bucket_name":'beforeupgadesasl'}, \
            ]

        for user in sdk_user_check:
            self.createBulkDocuments(user['bucket_name'],password=user['password'],input_key='post_demo_key_'+user['id'], end_num=self.num_items)


        if pass_updated is None:
            self.createBulkDocuments('beforeupgadesimple', input_key='post_demo_key_beforeupgadesimple', end_num=self.num_items)
        else:
            self.createBulkDocuments('beforeupgadesimple', password='p@ssword', input_key='post_demo_key_beforeupgadesimple',
                                     end_num=self.num_items)

        self.log.info("Online is ----------{0}".format(online))
        self.log.info("Password Updated is ----------{0}".format(pass_updated))
        if online is True and pass_updated is not None:
            self.log.info ("First Condition")
            self.execute_query(None, None, bucket='beforeupgadesimple',password='p@ssword')
            self.execute_query(None, None, bucket='beforeupgadesimple',password='p@ssword')
            self.execute_query(None, None, bucket='beforeupgadesasl', password='p@ssword')
        elif online is True and pass_updated is None:
            self.log.info("Second Condition")
            self.execute_query(query='CREATE INDEX simple_name ON beforeupgadesimple(name)', ddl='Yes',
                               bucket='beforeupgadesimple')
            self.execute_query(query='CREATE INDEX sasl_name ON beforeupgadesasl(name)', ddl='Yes',
                               bucket='beforeupgadesasl', password='p@ssword')
            self.execute_query(None, None, bucket='beforeupgadesimple')
            self.execute_query(None, None, bucket='beforeupgadesasl',password='p@ssword')
        elif online is None and pass_updated is None:
            self.log.info("Third Condition")
            if self.initial_version[0:5] != '3.1.5':
                self.execute_query("select city from `travel-sample` where city is not NULL", None, bucket='travel-sample')
                self.execute_query(None, None, bucket='beforeupgadesimple')
                self.execute_query(None, None, bucket='beforeupgadesasl', password='p@ssword')
        elif online is None and pass_updated is not None:
            self.log.info("Fourth Condition")
            if self.initial_version[0:5] != '3.1.5':
                self.execute_query("select city from `travel-sample` where city is not NULL", None, bucket='travel-sample',
                               password='p@ssword')
                self.execute_query(None, None, bucket='beforeupgadesimple', password='p@ssword')
                self.execute_query(None, None, bucket='beforeupgadesasl', password='p@ssword')

        if pass_updated is None and self.initial_version[0:5] != '3.1.5':
            self.execute_query(None, ddl='Yes', bucket='afterupgrade01', password='p@ssword')
            self.execute_query(None, ddl='Yes', bucket='afterupgrade02', password='p@ssword')

        if self.initial_version[0:5] != '3.1.5':
            self.execute_query(None, None, bucket='afterupgrade01', password='p@ssword')
            self.execute_query(None, None, bucket='afterupgrade02', password='p@ssword')

    def post_upgrade(self, simple=None, online=None):
        # 1. Create new bucket and users in the application
        # 2. Create new memcached connection with new and old users - New and old buckets
        # 3. Change roles for old user
        # 4. Change password for new users
        # 5. Change roles for new users


        #1. Create new bucket and new users in the system
        self.post_upgrade_buckets()
        self.post_upgrade_new_users_new_bucket()
        current_roles = RestConnection(self.master).retrieve_user_roles()
        self.check_roles(self.post_upgrade_user_role, current_roles)

        #2 Check for SDK connections post upgrade
        self.log.info ("-------------------- CHECK SDK CONNNECIONS POST UPGRADE USERS -----------------------------")
        self.check_sdk_connection_post_upgrade(online=online)
        self.sleep(10)

        self.log.info("-------------------- REBALANCE TO HAVE 1 NODE IN CLUSTER -----------------------------")
        self.cluster.rebalance(self.servers[:len(self.servers)], [], self.servers[1:self.num_servers])
        self.sleep(120)

        #3 check memcached for new users
        self.log.info("-------------------- CHECK MEMCACHED FOR NEW USERS -----------------------------")
        self.test_memcached_connection(self.master.ip, self.post_upgrade_user, self.post_upgrade_user_role)

        #4 check memcached for old users
        if simple is None:
            self.log.info("-------------------- CHECK MEMCACHED FOR OLD USERS -----------------------------")
            self.test_memcached_connection(self.master.ip, self.pre_upgrade_user, self.pre_upgrade_user_role)
            self.log.info("-------------------- CHECK ROLES FOR OLD USERS -----------------------------")
            self.check_roles(self.pre_upgrade_user_role, current_roles)
            self.sleep(30)
        #5 Change roles for pre-upgrade users
            self.log.info("-------------------- CHANGE ROLES OLD USERS -----------------------------")
            user_list, role_list = self.change_role_pre_upg_data()
            self.sleep(30)
            self.log.info("-------------------- CHECK MEMCACHED AFTER CHANGE ROLES OLD USERS -----------------------------")
            self.test_memcached_connection(self.master.ip, user_list, role_list)

        #6 check for views
        self.log.info("-------------------- VERIFY QUERIES POST UPGRADE -----------------------------")
        self.verify_all_queries()

        #Change password for user of upgraded buckets
        self.log.info("-------------------- CHANGE PASSWORD FOR UPGRADED BUCKET USERS -----------------------------")
        user_list, role_list = self.upgrade_pass_old_bucket()
        self.sleep(30)
        self.log.info("-------------------- CHECK MEMCACHED FOR UPGRADED BUCKET USERS -----------------------------")
        self.test_memcached_connection(self.master.ip, user_list, role_list)
        self.log.info("-------------------- CHECK SDK FOR UPGRADED BUCKET USERS -----------------------------")
        self.check_sdk_connection_post_upgrade(pass_updated=True,online=online)

    def check_cluster_compatiblity(self, server):
        rest = RestConnection(server)
        cluster_compatibility =  (rest.get_pools_default()['nodes'])[0]['clusterCompatibility']
        self.assertEquals(cluster_compatibility, 327680, 'Issue with cluster compatibility')


    def upgrade_all_nodes(self):
        self.pre_upgrade()
        self.setup_4_5_users()
        self.online_upgrade()
        self.check_cluster_compatiblity(self.master)
        self.post_upgrade(online=True)


    def upgrade_all_nodes_online_pre_4(self):
        self.pre_upgrade()
        self.online_upgrade()
        self.check_cluster_compatiblity(self.master)
        self.post_upgrade(online=True, simple=True)

    def upgrade_all_nodes_offline(self):
        self.pre_upgrade(offline=True)
        self.setup_4_5_users()
        upgrade_threads = self._async_update(upgrade_version=self.upgrade_version, servers=self.servers)
        for threads in upgrade_threads:
            threads.join()
        self.check_cluster_compatiblity(self.master)
        self.post_upgrade()


    def upgrade_all_nodes_offline_pre_4(self):
        self.pre_upgrade(offline=True)
        upgrade_threads = self._async_update(upgrade_version=self.upgrade_version, servers=self.servers)
        for threads in upgrade_threads:
            threads.join()
        self.check_cluster_compatiblity(self.master)
        self.post_upgrade(simple=True)
