
rule Trojan_BAT_CryptInject_CC_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 07 61 0a 06 18 58 0a 07 17 58 0b 07 1b 32 f0 } //6
		$a_03_1 = {03 8e 69 20 ?? ?? ?? ?? 1f 40 28 } //2
		$a_01_2 = {11 06 03 03 8e 69 12 07 28 } //2
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=10
 
}