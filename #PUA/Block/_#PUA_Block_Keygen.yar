
rule _#PUA_Block_Keygen{
	meta:
		description = "!#PUA:Block:Keygen,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b 65 79 6d 61 6b 65 72 20 62 79 20 53 69 72 61 58 2f 43 4f 52 45 } //1 keymaker by SiraX/CORE
	condition:
		((#a_01_0  & 1)*1) >=1
 
}