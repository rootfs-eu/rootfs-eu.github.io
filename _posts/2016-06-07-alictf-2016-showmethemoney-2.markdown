---
layout: post
title: ALICTF 2016 - showmethemoney
permalink: alictf-2016-showmethemoney-2/
date: '2016-06-07 11:07:05'
author: kmhn
tags:
- writeup
- ctf
- alictf2016
---

Unfortunately I didn't have much time to play this CTF, but this challenge caught my eyes and I decided to look at it at the last few hours of the tournament. I didn't manage to do it in time for the CTF due to the lack of time and some bone-headed mistake, but I went on with it anyways the day after.

**Note:** All the files related to this challenge can be found [here](https://github.com/khalednassar/ctf_writeups/tree/master/alictf2016/showmethemoney)

## Reconnaissance (and failures)
So we were given [showmethemoney.zip](https://github.com/khalednassar/ctf_writeups/blob/master/alictf2016/showmethemoney/showmethemoney_481bc5a72f7872a27e38a464ae97e935.zip) with the description:
> test:showmethemoney

Not very helpful, but we check out the contents and we find 3 files

1. `flag.txt`
2. `readme.txt`
3. `showmethemoney.exe`

`readme.txt` simply stated
> Show me the money to decrypt it.   
> ID: 09ce12e1-b775-4bda-af37-8abd886478ee   
> Filename: flag.txt

Not very informative yet, but seems highly likely that we're looking at some hypothetical ransomware situation. We need to dig deeper.

A quick look at `showmethemoney.exe` reveals that it is a .NET executable. Neat. So I fired up .NET Reflector to check it out. The application is relatively simple, just a couple of classes.

{: style="text-align:center"}
![appinternals](/content/images/2016/06/appinternals.png)

`AesCryptoHelper` is a rather peculiar wrapper class around .NET's `AESCryptoServiceProvider`, and it seems like a red herring because it's never referenced in the code that actually gets run. Let's dig a little deeper then.

![programcs](/content/images/2016/06/programcs.png)

There are some interesting things going on here, but for a quick rundown of how things happen starting with `Main`:

1. An `ID` is generated using `Guid.NewGuid()`
2. A `key` is generated using some combination of `System.Random` and another `Guid`
3. `RijndaelManaged` (AES in this case) is used to encrypt the contents of `flag.txt` with `key` and overwrite it with the base64 encoding of the ciphertext. Note that the `ECB` mode is used and the key size is 256 bits. I considered this more evidence that the `AesCryptoHelper` class is a red herring since it uses `CFB` mode, but I could still be mistaken at this point.
4. Both the generated `ID` and `key` are sent to a process listening on port 9999 on some server. The format of the message is `pi<ID>\0<key>`

With this in mind, I started looking at how could I possibly replicate the state of the `System.Random` PRNG to hopefully manage to recover the key. I frantically searched for any bugs or information leaks from GUIDs only to learn that this specific GUID implementation is a UUID version 4, as indicated by the character `4` at the beginning of the third part in the given ID `09ce12e1-b775-4bda-af37-8abd886478ee`. Those do not leak information (allegedly) like previous versions of UUID and are well, for all purposes of this challenge, a dead end. And this would be the reason why I couldn't finish this challenge during the CTF as I went on looking down this - incorrect - path wasting a good hour and a half before calling it quits for the day.

Fast forward a day later, I decided to list the information that I currently posses:

1. How the data was encrypted.
2. Which server the data was sent to.

After listing the 2nd item, I already knew what I missed. So I fired up nmap and decided to take a look at this server, which luckily was and is still running at the time of writing of this post. There were 3 open ports: `80 (http)`, `22 (ssh)`, and `9999`.
We know that `9999` is the port that the ransomware sends the keys to, but why is `80` open?

{: style="text-align:center"}
![greetings](/content/images/2016/06/greetings.png)

Oh look, what is this? [vvss](https://github.com/khalednassar/ctf_writeups/blob/master/alictf2016/showmethemoney/vvss)?
It turns out to be an ELF. IDA is fired up and after some quick messing around, we learn that this application uses 2 sqlite databases, namely `keys.db` and `keysbak.db`, the latter seemingly a backup of the former. It also accepts input of the forms:

1. `pi<string1>\0<string2>`
2. `pz<string1>\0`
3. `py\0`

For `(1)` and `(2)`, it forms a query that it executes on `keys.db`. `(1)` adds a new row to the table `keys` with columns `qid=string1`, `plain=string2` and `len=length(plain)`. This is clearly the routine used to store keys and their respective IDs that the ransomware sends. `(2)` reads the row with `qid=string1` and deletes it from the table afterwards. It's very likely that neither of these are of any help given what they do.

However, `(3)` runs a `select * from keys;` query on `keysbak.db`. Yep, there it is.

## Attack vector (Very Very Secure System)
So now that we know what we need to do, it's very easy to write a [python script](https://github.com/khalednassar/ctf_writeups/blob/master/alictf2016/showmethemoney/attack.py) that will send our query to the process. This is the output from the script:
```python
> python attack.py
Sent 4 bytes
Received: 5 bytes
ID:1

Received: 87 bytes
PLAIN:58897d583d888978b62469889d584472
QID:09ce12e1-b775-4bda-af37-8abd886478ee
LEN:32
```
The returned `QID` matches the `ID` in the given readme! Hence, our key is `58897d583d888978b62469889d584472`.

It's just as simple then to write [another script](https://github.com/khalednassar/ctf_writeups/blob/master/alictf2016/showmethemoney/decrypt.py) to decrypt the contents of `flag.txt`, and indeed we get the flag we're looking for: `alictf{Black_sh33p_w411}`

Moral of this writeup: do your reconnaissance well before going down rabbit holes. 
