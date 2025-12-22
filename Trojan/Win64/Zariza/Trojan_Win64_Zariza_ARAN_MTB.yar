
rule Trojan_Win64_Zariza_ARAN_MTB{
	meta:
		description = "Trojan:Win64/Zariza.ARAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 8d 0c 10 49 8b d3 80 e1 07 c0 e1 03 48 d3 ea 41 0f b6 c8 41 30 50 ff 41 2a c9 80 e1 07 49 8b d3 c0 e1 03 48 d3 ea 41 30 10 49 83 c0 02 4b 8d 04 02 48 83 f8 1e 72 c8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}