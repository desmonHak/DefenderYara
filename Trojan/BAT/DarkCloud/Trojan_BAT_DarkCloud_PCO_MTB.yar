
rule Trojan_BAT_DarkCloud_PCO_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.PCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 0c 11 0c 06 6f de 02 00 0a 6f df 02 00 0a } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}