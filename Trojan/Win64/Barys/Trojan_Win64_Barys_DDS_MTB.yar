
rule Trojan_Win64_Barys_DDS_MTB{
	meta:
		description = "Trojan:Win64/Barys.DDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 64 48 8b 4d 48 0f b6 04 01 83 f0 5e 8b 4d 64 ?? 8b 55 48 88 04 0a eb } //5
		$a_01_1 = {8b 45 64 ff c0 89 45 64 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}