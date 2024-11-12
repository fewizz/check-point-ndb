Small python module to read entries from `.NDB` files (like `fwauth.NDB`)

Usage:
```python
import ndb

data: bytes = ...
ndb.raise_on_invalid_magic(data)

# all entries
for entry_name, entry_data in ndb.for_each_entry_name_and_data(data):
    print(f"name: {entry_name.decode()}")
    print(f"data: {entry_data.decode()}")

# or specific entry
print("data of ABC", ndb.entry_data_by_name("ABC").decode())

```
