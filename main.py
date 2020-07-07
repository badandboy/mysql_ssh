
from pymysql import connect
from sshtunnel import SSHTunnelForwarder

#  指定SSH要连接跳转
ssh_server = 'xxx'  # sshhost
ssh_port = 22    # ssh端口
ssh_user = 'xxx'  # ssh用户
ssh_password = 'xxx'  # ssh密码

db_hostname = 'xxx'  # 要连接数据库的host
db_port = 'xxx'  # 要连接数据的端口
db_username = 'xxx'  # 要连接数据库的用户
db_password = 'xxx'  # 要连接数据库的密码
db_database = 'xxx'  # 要连接数据库的database

server = SSHTunnelForwarder(ssh_address_or_host=(ssh_server, ssh_port),  #  指定SSH中间登录地址和端口号
                            ssh_username=ssh_user,  #  指定地址B的SSH登录用户名
                            ssh_password=ssh_password,  #  指定地址B的SSH登录密码
                            local_bind_address=('127.0.0.1', 3307),  #  绑定本地地址A（默认127.0.0.1）及与B相通的端口（根据网络策略配置，若端口全放，则此行无需配置，使用默认即可）
                            remote_bind_address=(db_hostname, db_port)  #  指定最终目标C地址，端口号为mysql默认端口号3306
                            )

server.start()

#  设置mysql连接参数，地址与端口均必须设置为本地地址与端口
#  用户名和密码以及数据库名根据自己的数据库进行配置
db = connect(host="127.0.0.1", port=server.local_bind_port, user=db_username, passwd=db_password, db=db_database)

cursor = db.cursor()

sql = "select COUNT(1) from t_table"

# 执行SQL语句检查是否连接成功
cursor.execute("SELECT VERSION()")
result = cursor.fetchone()
print("Database version : %s " % result)
# 执行查询语句
cursor.execute(sql)
result = cursor.fetchone()
print("sql result : %s" % result)

# 关闭连接
db.close()
server.close()
