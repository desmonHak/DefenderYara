
rule Trojan_BAT_Nanocore_MZV_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.MZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 08 8e b7 17 59 13 0e 13 0d 2b 15 08 11 0d 08 11 0d 91 02 11 0d 03 5d 91 61 9c 11 0d 17 58 13 0d 11 0d 11 0e 31 e5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}