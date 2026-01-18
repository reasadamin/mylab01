from flask import Flask
import redis
import mysql.connector
import os

app = Flask(__name__)

redis_host = os.getenv('REDIS_HOST', 'redis')
mysql_host = os.getenv('MYSQL_HOST', 'mysql')

@app.route("/")
def hello():
    # Redis check
    r = redis.Redis(host=redis_host, port=6379)
    r.incr("hits")
    redis_hits = r.get("hits").decode()

    # MySQL check
    db = mysql.connector.connect(
        host=mysql_host,
        user="root",
        password="rootpass",
        database="testdb"
    )
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS visits (id INT AUTO_INCREMENT PRIMARY KEY, visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    cursor.execute("INSERT INTO visits () VALUES ()")
    db.commit()
    cursor.execute("SELECT COUNT(*) FROM visits")
    mysql_visits = cursor.fetchone()[0]

    return f"Redis hits: {redis_hits}<br>MySQL visits: {mysql_visits}"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)
