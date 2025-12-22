
rule Trojan_Win32_DllSideloadz_A_MTB{
	meta:
		description = "Trojan:Win32/DllSideloadz.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 2c 1c 88 44 3c 1c 47 88 5c 2c 1c 81 ff 00 01 00 00 7c c6 8b bc 24 1c 01 00 00 33 f6 85 ff 7e 56 33 db 33 ed 43 } //1
		$a_01_1 = {8b 4f 3c 8b b4 39 98 00 00 00 8b 94 39 9c 00 00 00 03 f7 33 c9 85 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}