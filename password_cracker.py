# password_cracker.py
# check hash against list of frequently-used passwords
# freecodecamp infosec project:
# https://www.freecodecamp.org/learn/information-security/information-security-projects/sha-1-password-cracker
# https://replit.com/@holleyst/boilerplate-SHA-1-password-cracker

import hashlib

# read in passwords and salts
pass_file = "top-10000-passwords.txt"
f = open(pass_file, "r")
passwords = [line.strip() for line in f]
f.close()

salt_file = "known-salts.txt"
f = open(salt_file, "r")
salts = [line.strip() for line in f]
f.close()


# crack_sha1_hash: given hash (and optional salts), check for unencrypted password
def crack_sha1_hash(hash, use_salts=False):
  if use_salts:
    for p in passwords:
      for s in salts:
        # try prepended and appended salt
        salted_hashes = [
          hashlib.sha1(p.encode() + s.encode()).hexdigest(),
          hashlib.sha1(s.encode() + p.encode()).hexdigest()
        ]
        if hash in salted_hashes:
          return p
  else:
    unsalted_passwords_dict = {
      hashlib.sha1(p.encode()).hexdigest(): p
      for p in passwords
    }
    if hash in unsalted_passwords_dict.keys():
      return unsalted_passwords_dict[hash]

  return "PASSWORD NOT IN DATABASE"
