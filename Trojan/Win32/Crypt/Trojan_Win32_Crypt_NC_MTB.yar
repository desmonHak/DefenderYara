
rule Trojan_Win32_Crypt_NC_MTB{
	meta:
		description = "Trojan:Win32/Crypt.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 55 00 66 8b ca 0f b7 d2 66 c1 e9 0c 81 e2 ff 0f 00 80 66 89 0d 14 c7 40 00 79 08 4a 81 ca 00 f0 ff ff 42 66 89 15 18 c7 40 00 66 85 c9 74 0f 66 83 f9 03 75 28 0f b7 ca 03 08 03 cf 01 31 } //2
		$a_01_1 = {ff 05 0c c7 40 00 45 45 39 1d 0c c7 40 00 72 b0 03 40 04 8b 48 04 a3 c0 c6 40 00 85 c9 75 87 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}