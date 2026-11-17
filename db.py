import sys, sqlite3
val = int(sys.argv[1])
c = sqlite3.connect('analytics.db')
c.execute('UPDATE visitor_usage SET total_events=20, is_premium=?', (val,))
c.commit()
print(c.execute('SELECT * FROM visitor_usage').fetchall())
