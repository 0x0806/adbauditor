import sqlite3, sys, json, os, shutil
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
expected = {}
def rows(con, t):
    cur = con.execute(f'select * from "{t}"')
    res = []
    for r in cur:
        res.append([ ('b:' + v.hex()) if isinstance(v, bytes) else v for v in r ])
    return res

# 1. mixed types, rowid alias, NULLs, negatives, big ints, floats, blobs, unicode
p = os.path.join(out, 'basic.db')
con = sqlite3.connect(p)
con.executescript('''
create table users(id integer primary key, name text not null, age integer, score real, avatar blob, note text default 'x');
create table "odd name"(a, b text, c numeric);
create index idx_users_name on users(name);
create view v as select name from users;
''')
con.executemany('insert into users(name,age,score,avatar,note) values(?,?,?,?,?)', [
    ('alice', 30, 1.5, b'\x00\x01\xff', 'héllo ✓'), ('bob', -5, -2.25, None, None), ('carol', 2**40, 0.0, b'', ''),
    ('dave', -2**40, 3.14159, b'abc', 'z'), ('erin', 0, 1e300, None, 'one'), ('frank', 1, None, None, 'two'), ('gina', 127, 1, None, 't'), ('hal', 128, 1, None, 't'),
    ('ian', 32768, 1, None, 't'), ('jo', 8388608, 1, None, 't'), ('kim', 2147483648, 1, None, 't'), ('lee', 140737488355328, 1, None, 't')])
con.execute('insert into "odd name" values (1,"two",3.5)')
con.execute('alter table users add column extra text')       # rows written before ALTER have fewer columns
con.commit(); con.close()
con = sqlite3.connect(p); expected['basic.db'] = {'users': rows(con, 'users'), 'odd name': rows(con, 'odd name')}; con.close()

# 2. overflow pages (1 KiB pages, big text/blob) + interior pages (many rows)
p = os.path.join(out, 'big.db')
con = sqlite3.connect(p)
con.execute('pragma page_size=1024'); con.execute('vacuum')
con.execute('create table docs(id integer primary key, body text, data blob)')
big = ''.join(chr(97 + (i % 26)) for i in range(20000))
con.execute('insert into docs(body,data) values (?,?)', (big, bytes(range(256)) * 40))
con.executemany('insert into docs(body,data) values (?,?)', [(f'row {i} ' + 'y' * (i % 300), None) for i in range(6000)])
con.commit(); con.close()
con = sqlite3.connect(p); expected['big.db'] = {'count': con.execute('select count(*) from docs').fetchone()[0], 'first': rows(con, 'docs')[:3], 'last': rows(con, 'docs')[-2:], 'page_size': con.execute('pragma page_size').fetchone()[0]}; con.close()

# 3. UTF-16le encoding
p = os.path.join(out, 'utf16.db')
con = sqlite3.connect(p)
con.execute("pragma encoding='UTF-16le'")
con.execute('create table t(id integer primary key, s text)')
con.executemany('insert into t(s) values(?)', [('héllo',), ('日本語',), ('🚀 rocket',)])
con.commit(); con.close()
con = sqlite3.connect(p); expected['utf16.db'] = {'t': rows(con, 't'), 'encoding': con.execute('pragma encoding').fetchone()[0]}; con.close()

# 4. WITHOUT ROWID + virtual-less
p = os.path.join(out, 'worowid.db')
con = sqlite3.connect(p)
con.execute('create table kv(k text primary key, v text) without rowid')
con.execute("insert into kv values('a','1')")
con.commit(); con.close()

# 5. WAL: rows exist only in the -wal file (connection kept open, no checkpoint)
p = os.path.join(out, 'wal.db')
con = sqlite3.connect(p)
con.execute('pragma journal_mode=wal'); con.execute('pragma wal_autocheckpoint=0')
con.execute('create table t(id integer primary key, v text)')
con.commit()
con.execute('pragma wal_checkpoint(truncate)')
con.executemany('insert into t(v) values(?)', [(f'wal-row-{i}',) for i in range(50)])
con.commit()
shutil.copy(p, p + '.copy'); shutil.copy(p + '-wal', p + '.copy-wal')
expected['wal.db'] = {'t': rows(con, 't')}
con.close()
os.replace(p + '.copy', os.path.join(out, 'wal-main.db')); os.replace(p + '.copy-wal', os.path.join(out, 'wal-main.db-wal'))
json.dump(expected, open(os.path.join(out, 'expected.json'), 'w'))
