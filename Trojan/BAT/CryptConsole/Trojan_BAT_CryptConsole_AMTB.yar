
rule Trojan_BAT_CryptConsole_AMTB{
	meta:
		description = "Trojan:BAT/CryptConsole!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {45 6e 61 62 6c 65 4c 55 41 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 } //EnableLUA /t REG_DWORD /d 0  2
		$a_80_1 = {63 65 72 74 75 74 69 6c 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 } //certutil -urlcache -split -f  2
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 72 65 61 6c 76 69 72 75 73 2e 66 61 6b 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 73 63 76 68 6f 73 74 } //https://realvirus.fake.com/download/scvhost  2
		$a_80_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6e 6f 74 73 76 63 68 6f 73 74 2e 65 78 65 } //C:\Windows\System32\notsvchost.exe  2
		$a_80_4 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 } //powershell.exe -EncodedCommand  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}