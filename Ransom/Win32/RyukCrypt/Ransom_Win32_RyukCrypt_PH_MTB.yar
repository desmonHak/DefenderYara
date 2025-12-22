
rule Ransom_Win32_RyukCrypt_PH_MTB{
	meta:
		description = "Ransom:Win32/RyukCrypt.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 e9 04 ba ?? ?? ?? ?? 90 13 be ?? ?? ?? ?? ba ?? ?? ?? ?? ba ?? ?? ?? ?? 90 13 ba ?? ?? ?? ?? 31 06 bb ?? ?? ?? ?? 90 13 83 c6 04 83 e9 04 90 13 83 f9 05 7d ?? e9 } //1
		$a_03_1 = {bb f4 6a 08 fa 30 06 90 13 46 90 13 49 90 13 83 f9 01 7d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_RyukCrypt_PH_MTB_2{
	meta:
		description = "Ransom:Win32/RyukCrypt.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 00 6e 00 63 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 EncReadMe.html
		$a_01_1 = {2e 00 65 00 6e 00 63 00 } //1 .enc
		$a_01_2 = {6e 65 74 20 73 74 6f 70 20 41 6e 74 69 76 69 72 75 73 } //1 net stop Antivirus
		$a_01_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 20 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 20 00 61 00 6c 00 6c 00 20 00 2f 00 20 00 71 00 75 00 69 00 65 00 74 00 } //1 cmd.exe / c vssadmin delete shadows / all / quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}