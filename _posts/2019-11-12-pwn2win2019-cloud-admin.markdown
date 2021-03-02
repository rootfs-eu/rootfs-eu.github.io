---
layout: post
title: Pwn2Win CTF 2019 - Cloud Admin
permalink: pwn2win2019-cloud-admin/
date: '2019-11-12 10:30:00'
author: kmhn
tags:
- writeup
- ctf
---

 **Category:** Miscellaneous, **Solves:** 7, **Score:** 383

> I was able to capture a simple database from the Organization's virtual machine. After gaining access as a cloud admin, I also managed to dump the VM memory. Maybe there is some important messages in this database...
> 
> Link: [https://cloud.ufscar.br:8080/v1/AUTH\_c93b694078064b4f81afd2266a502511/static.pwn2win.party/cloud\_admin\_cbbeacb2025a5c979da7e9eddbe9119cf05fbd9d2b115f7ec8cc1810040ad82d.tar.gz](https://cloud.ufscar.br:8080/v1/AUTH_c93b694078064b4f81afd2266a502511/static.pwn2win.party/cloud_admin_cbbeacb2025a5c979da7e9eddbe9119cf05fbd9d2b115f7ec8cc1810040ad82d.tar.gz)
> 
> Mirror: [https://static.pwn2win.party/cloud\_admin\_cbbeacb2025a5c979da7e9eddbe9119cf05fbd9d2b115f7ec8cc1810040ad82d.tar.gz](https://static.pwn2win.party/cloud_admin_cbbeacb2025a5c979da7e9eddbe9119cf05fbd9d2b115f7ec8cc1810040ad82d.tar.gz)

<!--kg-card-end: markdown--><!--kg-card-begin: markdown-->
## Analysis

We're given an SQLite database, `data.db`, and a memory dump from a virtual machine, `memory.dump`. Initially, we dumped the contents of the database to see what we're dealing with:

### Database

    $ sqlite3 data.db
    SQLite version 3.22.0 2018-01-22 18:45:57
    Enter ".help" for usage hints.
    sqlite> .tables
    MSGS
    sqlite> .dump MSGS
    PRAGMA foreign_keys=OFF;
    BEGIN TRANSACTION;
    CREATE TABLE MSGS(ID int, CONTENT text);
    INSERT INTO MSGS VALUES(0,'7f80b3887fa22a29c02d302dbd72d9ee2df1ef86c915210e153375aa2684cab1004ede5787b4adb2bf');
    INSERT INTO MSGS VALUES(0,'a83acee0c65881a61cf2d8c91624bb2d5d5d63ddbd26f834a03aa3c3e79407a1fdbf2d6557b9');
    INSERT INTO MSGS VALUES(0,'3163da8582380813b8798571e2900aacd1602ac218d401e72cd784d1aa809eb39e108f601c04');
    INSERT INTO MSGS VALUES(0,'c91f4bdd9b199ac7a8f1d1aa8a5d30668f62b0a6f28855f893af3bb3b78bb600c15564c5198b175aef535711f17895b2a7423cdaf617d4df23cd0f8840f6326188cff29c32fbb52bb2181fc742d98dc966bf28b2');
    INSERT INTO MSGS VALUES(0,'d97a56b474d7bb2a530f5e4fee4b814050f08f89883867497ef4d922931a6a47af9edc8');
    COMMIT;

There's a table, `MSGS`, which contains some hex-encoded strings. The message `c91f4bdd9b199ac7a8f1d1aa8a5d30668f62b0a6f28855f893af3bb3b78bb600c15564c5198b175aef535711f17895b2a7423cdaf617d4df23cd0f8840f6326188cff29c32fbb52bb2181fc742d98dc966bf28b2` is particularly interesting because it is quite long compared to the rest. Just decoding them yields gibberish. Seeing that, and given the challenge description, we assumed one of these messages is the flag. It is possibly encrypted in some fashion and we're supposed to figure out how to decrypt it by making use of the memory dump.

### Memory dump

Initially, we did a bit of `strings` and `grep` on the memory dump to see what kind of information we can glean from it. We learned that:

1. This is a memory dump of a 64-bit Ubuntu 16.04.5 VM (the specific version comes into play again later).
2. There's something about a `secret_msg.py` script, with some strings pointing to the usage of AES.

A teammate had extracted the script with a bit of ad-hoc analysis at this point:

    import sqlite3
    import requests
    import base64
    import os
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    id_count = 0
    key = None
    def create_db():
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE MSGS(ID int, CONTENT text)")
        conn.commit()
        conn.close()
    
    def enc(msg):
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        enc = encryptor.update(msg) + encryptor.finalize()
        return (iv + encryptor.tag + enc).encode("hex")
    
    def insert_new_message(msg):
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO MSGS VALUES(" + str(id_count) + ", '" + enc(msg) + "')")
        conn.commit()
        conn.close()
    
    def test():
        global key
        key = base64.b64decode(requests.get('https://172.17.0.2:5000', verify=False).content)
        create_db()
        while(True):
            try:
                msg = requests.get('https://172.17.0.2:5000', verify=False).content
                insert_new_message(msg)
            except:
                break
    test()

After going through the script, we noticed a few things:

1. Our assumption about the messages being encrypted was correct. It is AES in GCM mode and nothing looks immediately wrong with the crypto. Pwn2Win 2018 had a [challenge that involved making use of a vulnerability of the AES-GCM implementation in the Python `cryptography` library](https://fireshellsecurity.team/pwn2win-gcm/). That specific vulnerability does not apply in this case, though, due to the nature of the challenge.
2. The key used to encrypt the messages as well as the messages themselves were retrieved over HTTPS from some service running at `172.17.0.2:5000`.
3. The key is a `str` object referenced by a global in module scope, which means that there'll always be at least one reference to it and it won't be collected by the garbage collector.

The most obvious path to solve the challenge is recovering the key from memory. If it is not, and assuming the key is randomly generated using a CSPRNG, this would become unsolvable.

## Solution

We used the [volatility framework](https://www.volatilityfoundation.org/) to analyze the memory dump. After some more grepping, we learned that the Linux kernel version of the snapshotted machine is `4.4.0-131-generic`. We used [volatility profile builder](https://github.com/bannsec/volatility_profile_builder) to create an Ubuntu 16.04.5 (xenial-20191024) profile and loaded up the dump.

Listing the processes that were running:

    Volatility Foundation Volatility Framework 2.6
    Pid Uid Gid Arguments                                                       
    1 0 0 /sbin/init                                                      
    2 0 0 [kthreadd]                                                      
    3 0 0 [ksoftirqd/0]                                      
    [...snip...]                                        
    1149 1000 1000 -bash                                                           
    7288 0 0 [kworker/u2:2]                                                  
    7307 0 0 [kworker/u2:0]                                                  
    7310 1000 1000 python secret_msg.py                                            
    7314 0 0 [kworker/0:0]       

And here's the process we're looking for, the Python 2 (identified the installed Python interpreter version during initial analysis) process with PID `7310`.

Since it is Python 2, we know that the key is going to be of type `str` unlike Python 3 where it would have been `bytes` instead. We started digging through the [CPython 2.7](https://github.com/python/cpython/tree/2.7) source code to understand how Python strings are represented in memory.

The [layout for `str` instances on a 64-bit architecture](https://github.com/python/cpython/blob/2.7/Include/stringobject.h) is as follows (in pseudocode):

    PyStringObject {
       ulong reference_count;
       PyTypeObject * string_type;
       long string_length;
       long string_hash;
       int string_state;
       char string_value[string_length + 1]
    }

Where `PyTypeObject` refers to `PyString_Type` in this case, and has a [layout that starts as](https://github.com/python/cpython/blob/2.7/Objects/stringobject.c):

    PyString_Type {
       ulong reference_count;
       PyTypeObject * type;
       long string_object_length;
       char * name = "str\x00";
       [...snip unnecessary attributes...]
    }

Our strategy was: find all the `str` instances in the process memory and filter them down to possible AES key candidates, then try all of them. In detail, the plan is to:

1. Identify all byte sequences that represent `str\x00`, that is the ASCII string `str` with a terminating null byte (i.e. a regular C string).
2. Look for all the locations in memory that reference the identified byte sequences' addresses. One of them should be at `PyString_Type + 0x18` (as indicated by the `PyString_Type` model), and ideally, there will be only one instance of `PyString_Type` in memory.
3. Look for all the locations that reference the address of `PyString_Type`, these should be the second field of `str` instances, referencing the type of the instance. For each of the locations `location_address` that fit the criterion, we'll have `location_address + 0x8` be the address where the corresponding `str` instance resides.
4. Filter them down to ones that could be used as an AES key based on length.

Implementing this process with volatility was relatively easy since it provides a handy Python shell that we could use to analyze the process memory, allowing us to read data from the process using virtual addresses, as if we were actually the process itself.

Here is the volatility shell session, implementing the above process, that was used to solve the challenge during the CTF, annotated wherever clarification is useful:

    >>> cc(pid=7310)
    Current context: process python, pid=7310 DTB=0x355b4000
    >>> asp = proc().get_process_address_space()
    >>> sm = proc().search_process_memory
    >>> # A helper function to convert a list of integers into
    >>> # little-endian byte string representations of them
    >>> def conv(li):
    ... return list(map(lambda y: y[::-1], map(lambda x: hex(x)[2:-1].decode('hex') if len(hex(x)[2:-1]) % 2 == 0 else ('0' + hex(x)[2:-1]).decode('hex'), li)))
    ...
    >>> # Helper function to right-pad a list of strings to the right with 0
    >>> # bytes until they are plen long. Does not apply any transformations
    >>> # to strings that are at least plen bytes long.
    >>> def rpad(li, plen=8):
    ... return list(map(lambda x: x + ('\x00' * (plen - len(x))), li))
    ... 
    >>> # Find all memory addresses that point to the sequence 'str\x00'
    >>> str_insts = [x for x in sm(['str\x00'])]
    >>> str_insts
    [4246750L, 4247954L, 4256116L, [...snip...] 140734922346175L]
    >>> ptr_str_insts = rpad(conv(str_insts))
    >>> # Locate all the memory addresses that point to byte sequences
    >>> # representing any of the previously identified memory addresses
    >>> ref_str_insts = [x for x in sm(ptr_str_insts)]
    >>> ref_str_insts
    [9411704L]
    >>> # Only one of them was found, which would ideally be the third field
    >>> # in the PyString_Type object. Subtract 0x18 to get the address of
    >>> # PyString_Type
    >>> ref_str_insts = [9411704L - 0x18]
    >>> ref_str_insts
    [9411680L]
    >>> # Find all the memory locations referencing PyString_Type.
    >>> str_type_ptrs = [x for x in sm(rpad(conv(ref_str_insts)))]
    >>> len(str_type_ptrs)
    41867
    >>> # Helper function to convert a byte sequence into an integer.
    >>> # Assumes the byte sequence is a little-endian ordering.
    >>> def s_to_ulong(s):
    ... return int(s[::-1].encode('hex'), 16)
    ... 
    >>> # Helper function to read a Python `str` from memory, given its
    >>> # address. If a string is longer than maxlen then it returns the 
    >>> # empty string.
    >>> def read_str(asp, off, maxlen=0x100):
    ... strlen = s_to_ulong(asp.read(off + 0x10, 8))
    ... if strlen > maxlen:
    ... return ''
    ... return asp.read(off + 0x24, strlen)
    ... 
    >>> str_ptrs = list(map(lambda x: x - 0x8, str_type_ptrs))
    >>> strs = list(map(lambda x: read_str(asp, x, maxlen=0x20), str_ptrs))
    >>> candidate_keys = list(filter(lambda x: len(x) == 16 or len(x) == 32, strs))
    >>> len(candidate_keys)
    1377
    >>> len16 = list(filter(lambda x: len(x) == 16, candidate_keys))
    >>> len32 = list(filter(lambda x: len(x) == 32, candidate_keys))
    >>> with open('candidate_keys_16', 'wb') as fs:
    ... map(fs.write, len16) and None
    ... 
    >>> with open('candidate_keys_32', 'wb') as fs:
    ... map(fs.write, len32) and None
    ... 

**Side-note:** In hindsight, we should have also extracted 192-bit long strings. We made a mistake there, but it's very uncommon to see AES keys of that length. However, as luck would have it, the actual key was 128 bits long.

After extracting the keys, we tried them all with another Python script:

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
    from cryptography.exceptions import InvalidTag
    
    
    def dec(msg, key):
        msg = msg.decode('hex')
        iv = msg[:12]
        msg = msg[12:]
        tag = msg[:16]
        ct = msg[16:]
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        return decryptor.update(ct) + decryptor.finalize()
    
    
    msgs = [
        '7f80b3887fa22a29c02d302dbd72d9ee2df1ef86c915210e153375aa2684cab1004ede5787b4adb2bf',
        'a83acee0c65881a61cf2d8c91624bb2d5d5d63ddbd26f834a03aa3c3e79407a1fdbf2d6557b9',
        '3163da8582380813b8798571e2900aacd1602ac218d401e72cd784d1aa809eb39e108f601c04',
        'd97a56b474d7bb2a530f5e4fee4b814050f08f89883867497ef4d922931a6a847af9edc8',
        'c91f4bdd9b199ac7a8f1d1aa8a5d30668f62b0a6f28855f893af3bb3b78bb600c15564c5198b175aef535711f17895b2a7423cdaf617d4df23cd0f8840f6326188cff29c32fbb52bb2181fc742d98dc966bf28b2',
    ]
    
    
    def try_keys():
        with open('candidate_keys_16', 'rb') as fs:
            data = fs.read()
        keys16 = [data[i:i+16] for i in range(0, len(data), 16)]
    
        with open('candidate_keys_32', 'rb') as fs:
            data = fs.read()
        keys32 = [data[i:i+32] for i in range(0, len(data), 32)]
    
        keys = keys16 + keys32
        print('Loaded {} keys'.format(len(keys)))
    
        for k in keys:
            try:
                decrypted = [dec(m, k) for m in msgs]
                if decrypted:
                    print('Decrypted messages using key {}'.format(repr(k)))
                    print(decrypted)
                    break
            except InvalidTag as e:
                pass
            except Exception as e:
                print(e)
    
    
    try_keys()

    $ python solve.py 
    Loaded 1377 keys
    Decrypted messages using key '\x01\x01\x85\xc8/;\xce\xa3{\x1fL3Y`\xe7\xdb'
    ['9-999-999-999', 'Cleoswaldo', 'A flag \xc3\xa9:', 'shutdown', 'CTF-BR{d3v14_73r_cr1p706r4f4d0_4n735_d3_ch364r_n4_cl0ud}']

## Flag

`CTF-BR{d3v14_73r_cr1p706r4f4d0_4n735_d3_ch364r_n4_cl0ud}`

<!--kg-card-end: markdown-->
