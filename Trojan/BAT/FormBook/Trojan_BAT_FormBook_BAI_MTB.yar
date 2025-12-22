
rule Trojan_BAT_FormBook_BAI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 13 05 07 ?? ?? 00 00 0a 13 06 11 04 11 05 11 06 ?? ?? 00 00 0a 13 07 03 73 05 00 00 0a 13 08 11 08 11 07 16 73 06 00 00 0a 13 09 73 07 00 00 0a 13 0a 11 09 11 0a ?? ?? 00 00 0a 11 0a ?? ?? 00 00 0a 0c 1f 64 0d dd 0f 00 00 00 11 0a 39 07 00 00 00 11 0a ?? ?? 00 00 0a dc dd 0f 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}