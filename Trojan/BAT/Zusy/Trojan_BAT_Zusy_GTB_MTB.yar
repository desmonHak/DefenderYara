
rule Trojan_BAT_Zusy_GTB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 5e 26 16 13 0a 2b 2b 11 05 11 0a 8f 18 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd 11 06 2a } //10
		$a_01_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_2 = {6b 6f 69 00 55 6e 6c 6f 63 6b 65 72 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 } //1 潫i湕潬正牥攮數㰀潍畤敬>
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}