
rule _#PUA_Block_WildRigMulti{
	meta:
		description = "!#PUA:Block:WildRigMulti,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b d1 80 32 ?? 41 ff c0 48 8d 52 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}