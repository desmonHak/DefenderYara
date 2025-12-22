
rule Trojan_BAT_Zusy_AR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 09 02 09 91 03 09 91 61 d2 9c 09 17 58 0d 09 02 8e 69 fe 04 13 04 11 04 2d e5 } //25
		$a_01_1 = {64 65 6e 34 34 34 2e 65 78 65 } //5 den444.exe
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*5) >=30
 
}