
rule Trojan_BAT_WMITask_HB_MTB{
	meta:
		description = "Trojan:BAT/WMITask.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 11 72 01 00 00 70 0a 02 6f 14 00 00 0a 72 ?? 00 00 70 6f 15 00 00 0a 06 72 ?? 00 00 70 28 16 00 00 0a 0b 02 6f 14 00 00 0a 72 ?? 00 00 70 6f 15 00 00 0a 0c 07 08 28 06 00 00 06 [0-24] 26 de 00 16 2a } //1
		$a_03_1 = {00 00 70 6f 15 00 00 0a 17 8d ?? ?? 00 01 25 16 1f 2c 9d 6f ?? 00 00 0a 0b 06 07 28 90 09 19 00 02 6f ?? 00 00 0a 72 01 00 00 70 6f ?? 00 00 0a 0a 02 6f ?? 00 00 0a 72 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}