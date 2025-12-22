
rule Trojan_BAT_ReaderDB_EBIV_MTB{
	meta:
		description = "Trojan:BAT/ReaderDB.EBIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 1d 13 05 2b c2 16 0a 18 13 05 2b bb 03 04 61 1f 2f 59 06 61 ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 06 1f 7f 91 ?? ?? ?? ?? ?? 59 13 05 2b 9b 11 07 1f 7e 93 ?? ?? ?? ?? ?? 59 2b ef } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}