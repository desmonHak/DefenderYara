
rule Trojan_BAT_Bartblaze_MCP_MTB{
	meta:
		description = "Trojan:BAT/Bartblaze.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 38 31 36 33 39 38 39 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 50 6f 6c 69 63 79 00 32 38 30 33 32 30 32 33 31 39 36 31 39 4a 4b 47 46 4b 5a 41 46 48 4b 49 4b 48 46 5a 48 44 54 4b 47 48 41 47 5a } //1 㠳㘱㤳㤸攮數㰀潍畤敬>潐楬祣㈀〸㈳㈰ㄳ㘹㤱䭊䙇婋䙁䭈䭉䙈䡚呄䝋䅈婇
	condition:
		((#a_01_0  & 1)*1) >=1
 
}