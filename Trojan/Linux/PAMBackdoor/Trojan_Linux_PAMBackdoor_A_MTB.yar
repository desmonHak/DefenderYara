
rule Trojan_Linux_PAMBackdoor_A_MTB{
	meta:
		description = "Trojan:Linux/PAMBackdoor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 e8 48 8b 45 f8 48 01 d0 0f b6 08 48 8b 45 f8 ba 00 00 00 00 48 f7 75 f0 48 8b 45 e0 48 01 d0 0f b6 10 48 8b 75 e8 48 8b 45 f8 48 01 f0 31 ca 88 10 48 83 45 f8 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}