
rule Trojan_Win32_TrickBot_BAA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {24 18 8b 74 24 14 8b 4c 24 10 8b 7c 24 0c 85 d2 74 ?? 52 ac 30 07 5a 47 4a e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}