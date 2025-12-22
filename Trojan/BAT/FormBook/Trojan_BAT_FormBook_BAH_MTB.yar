
rule Trojan_BAT_FormBook_BAH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 16 73 06 00 00 0a 13 05 73 07 00 00 0a 13 06 11 05 11 06 ?? ?? 00 00 0a 11 06 ?? ?? 00 00 0a 13 07 dd 50 00 00 00 11 06 39 07 00 00 00 11 06 ?? ?? 00 00 0a dc 11 05 39 07 00 00 00 11 05 ?? ?? 00 00 0a dc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}