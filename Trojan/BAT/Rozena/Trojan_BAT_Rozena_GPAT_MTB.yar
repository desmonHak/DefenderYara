
rule Trojan_BAT_Rozena_GPAT_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GPAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 43 72 65 61 74 65 54 68 72 65 61 64 00 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 00 2e 63 74 6f 72 } //8 楖瑲慵䅬汬捯嘀物畴污牐瑯捥t牃慥整桔敲摡圀楡䙴牯楓杮敬扏敪瑣⸀瑣牯
	condition:
		((#a_01_0  & 1)*8) >=8
 
}