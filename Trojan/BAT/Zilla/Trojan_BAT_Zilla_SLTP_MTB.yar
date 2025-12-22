
rule Trojan_BAT_Zilla_SLTP_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 35 00 00 06 25 28 0b 00 00 0a 6f 36 00 00 06 0a 12 00 28 0c 00 00 0a 17 33 05 28 65 00 00 06 28 6a 00 00 06 28 40 00 00 06 73 88 00 00 06 28 8d 00 00 06 22 00 00 40 40 28 2f 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}