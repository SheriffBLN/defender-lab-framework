# Alert: Data Encrypted for Impact

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1486  
**Nazwa:** Data Encrypted for Impact  
**Taktyki:** Impact  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Impact
Technique ID: T1486
Technique Name: Data Encrypted for Impact
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### PureLocker Ransom Note
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
echo T1486 - Purelocker Ransom Note > %USERPROFILE%\Desktop\YOUR_FILES.txt
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1486\PureLocker_Ransom_Note/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
del %USERPROFILE%\Desktop\YOUR_FILES.txt >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1486\PureLocker_Ransom_Note/cleanup_1.cmd)

### Data Encrypted with GPG4Win
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Set-Content -Path "#{File_to_Encrypt_Location}" -Value "populating this file with some text"  # Create the test.txt file again in case prereqs failed
cmd /c "`"C:\Program Files (x86)\GnuPG\bin\gpg.exe`" --passphrase 'SomeParaphraseBlah' --batch --yes -c `"#{File_to_Encrypt_Location}`""
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1486\Data_Encrypted_with_GPG4Win/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item -Path "#{File_to_Encrypt_Location}" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "#{File_to_Encrypt_Location}.gpg" -Force -ErrorAction SilentlyContinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1486\Data_Encrypted_with_GPG4Win/cleanup_1.ps1)

### Data Encrypt Using DiskCryptor
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
""%PROGRAMFILES%\dcrypt"\#{dcrypt_exe}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1486\Data_Encrypt_Using_DiskCryptor/test_1.cmd)

### Akira Ransomware drop Files with .akira Extension and Ransomnote
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
1..100 | ForEach-Object { $out = new-object byte[] 1073741; (new-object Random).NextBytes($out); [IO.File]::WriteAllBytes("c:\test.$_.akira", $out) }
echo "Hi friends" >> $env:Userprofile\Desktop\akira_readme.txt
echo "" >> $env:Userprofile\Desktop\akira_readme.txt
echo "Whatever who you are and what your title is if you' re reading this it means the internal infrastructure of your company is fully or partially dead, all your backups - virtual, physical - everything that we managed to reach - are completely removed. Moreover, we have taken a great amount of your corporate data prior to encryption  Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue. We're fully aware of what damage we caused by locking your internal sources. At the moment. you have to know: " >> $env:Userprofile\Desktop\akira_readme.txt
echo "1. Dealing with us you will save A LOT due to we are not interested in ruining your financially. We will study in depth your finance, bank income statements, your savings, investments etc. and present our reasonable demand to you. If you have an active cyber insurance, let us know and we will guide you how to properly use it. Also, dragging out the negotiation process will lead to failing of a deal" >> $env:Userprofile\Desktop\akira_readme.txt
echo "2. Paying us you save your TIME, MONEY, EFFORTS and be back on track within 24 hours approximately. Our decryptor works properly on any files or systems, so you will be able to check it by requesting a test decryption service from the beginning of our conversation. [f you decide to recover on your own, keep in mind that you can permanently lose access to some files or accidently corrupt them — in this case we won't be able to help.  " >> $env:Userprofile\Desktop\akira_readme.txt
echo "3. The security report or the exclusive first-hand information that you will receive upon reaching an agreement is of a great value, since NO full audit of your network will show you the vulnerabilities that we' ve managed to detect and used in order to get into. identify backup solutions and upload your data." >> $env:Userprofile\Desktop\akira_readme.txt
echo "4. As for your data, if we fail to agree, we will try to sell personal information/trade secrets/databases/source codes — generally speaking, everything that has a value on the darkmarket - to multiple threat actors at ones." >> $env:Userprofile\Desktop\akira_readme.txt
echo "Then all of this will be published in our blog -" >> $env:Userprofile\Desktop\akira_readme.txt
echo "" >> $env:Userprofile\Desktop\akira_readme.txt
echo "https://akira.onion" >> $env:Userprofile\Desktop\akira_readme.txt
echo "" >> $env:Userprofile\Desktop\akira_readme.txt
echo "5. We're more than negotiable and will definitely find the way to settle this quickly and reach an agreement which will satisfy both of us" >> $env:Userprofile\Desktop\akira_readme.txt
echo "" >> $env:Userprofile\Desktop\akira_readme.txt
echo "If you' re indeed interested in our assistance and the services we provide you can reach out to us following simple instructions:" >> $env:Userprofile\Desktop\akira_readme.txt
echo "" >> $env:Userprofile\Desktop\akira_readme.txt
echo "1. Install TOR Browser to get access to our chat room - https://www.torproject.org/download/." >> $env:Userprofile\Desktop\akira_readme.txt
echo "2. Paste this link - https://akira.onion" >> $env:Userprofile\Desktop\akira_readme.txt
echo "3. Use this code - - to log into our chat." >> $env:Userprofile\Desktop\akira_readme.txt
echo "" >> $env:Userprofile\Desktop\akira_readme.txt
echo "Keep in mind that the faster you will get in touch, the less damage we cause" >> $env:Userprofile\Desktop\akira_readme.txt
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1486\Akira_Ransomware_drop_Files_with_.akira_/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
del $env:Userprofile\Desktop\akira_readme.txt 
del c:\test.*.akira
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1486\Akira_Ransomware_drop_Files_with_.akira_/cleanup_1.ps1)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1486)
