
rule _#PUA_Block_ShopperPro{
	meta:
		description = "!#PUA:Block:ShopperPro,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {6a 73 64 72 76 2e 70 64 62 } //jsdrv.pdb  1
		$a_80_1 = {72 65 70 6a 73 2e 73 68 6f 70 70 65 72 2d 70 72 6f 2e 63 6f 6d } //repjs.shopper-pro.com  2
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 53 68 6f 70 70 65 72 50 72 6f 5c 4a 73 44 72 69 76 65 72 } //SOFTWARE\ShopperPro\JsDriver  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=4
 
}