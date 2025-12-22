
rule Trojan_BAT_AsyncRAT_GTF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 0d 00 20 ?? 03 00 00 28 ?? 00 00 0a 00 00 17 0d 2b ef } //5
		$a_03_1 = {06 26 00 28 ?? 00 00 06 26 28 ?? 00 00 06 16 fe 01 0b 07 2c 07 16 28 13 00 00 0a 00 00 de 05 0c 00 00 de 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}