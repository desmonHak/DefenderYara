
rule Trojan_BAT_Heracles_PPCB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PPCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 20 02 07 6f b6 00 00 0a 03 07 03 6f b5 00 00 0a 5d 6f b6 00 00 0a 61 0c 06 07 08 d2 9c 07 17 58 0b 07 02 6f b5 00 00 0a 32 d7 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}