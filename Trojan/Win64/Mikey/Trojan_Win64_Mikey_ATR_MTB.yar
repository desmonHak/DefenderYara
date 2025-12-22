
rule Trojan_Win64_Mikey_ATR_MTB{
	meta:
		description = "Trojan:Win64/Mikey.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 00 02 01 0b 01 0e 25 00 76 02 00 } //6
		$a_01_1 = {60 08 00 00 10 00 00 00 94 05 00 00 10 00 } //4
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}