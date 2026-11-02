"""Completed-journal root totals; no database scan at root boundaries."""
class RootTotals:
    def __init__(self, rows=None):
        self.rows = {root: dict(files=row['files'], bytes=row['bytes'])
                     for root, row in (rows or {}).items()}

    def add(self, record):
        row = self.rows.setdefault(record['root'], dict(files=0, bytes=0))
        row['files'] += 1
        row['bytes'] += record['bytes']

    def get(self, root):
        return dict(self.rows.get(root, dict(files=0, bytes=0)))

    def snapshot(self):
        return {root: dict(row) for root, row in self.rows.items()}

    def validate(self, roots, status):
        if set(self.rows) - set(roots):
            raise ValueError('root totals contain an unknown root')
        for row in self.rows.values():
            if any(type(row[k]) is not int or row[k] < 0 for k in ('files', 'bytes')):
                raise ValueError('invalid root totals')
        if any(sum(row[k] for row in self.rows.values()) != status[k]
               for k in ('files', 'bytes')):
            raise ValueError('root totals do not match completed counters')
        return self
