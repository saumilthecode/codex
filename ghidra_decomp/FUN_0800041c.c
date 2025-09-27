
uint FUN_0800041c(int param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  
  uVar2 = DAT_0800045c;
  puVar1 = DAT_08000450;
  uVar6 = *DAT_08000450;
  uVar5 = DAT_08000454 - DAT_08000458;
  if (uVar6 == 0) {
    *DAT_08000450 = DAT_0800045c;
    uVar3 = param_1 + uVar2;
    uVar6 = uVar2;
  }
  else {
    uVar3 = param_1 + uVar6;
  }
  if (uVar3 <= uVar5) {
    *puVar1 = uVar3;
    return uVar6;
  }
  puVar4 = (undefined4 *)FUN_080285f8();
  *puVar4 = 0xc;
  return 0xffffffff;
}

