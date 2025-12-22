
rule Trojan_Win32_Neoreblamy_NIV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0d 8b 4f 04 03 ce 33 0c 30 e8 be f2 ff ff 8b 47 08 8b 4f 0c 03 ce 33 0c 30 } //1
		$a_01_1 = {47 d1 e8 f6 45 f8 01 89 45 f4 74 08 0d 00 00 00 80 89 45 f4 d1 6d f8 49 75 dc } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}