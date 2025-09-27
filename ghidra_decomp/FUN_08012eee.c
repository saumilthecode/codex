
undefined4 *
FUN_08012eee(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int *param_7,int param_8,int param_9,int param_10,
            int param_11,uint *param_12)

{
  uint *puVar1;
  undefined1 uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 uStack_28;
  
  puVar1 = param_12;
  local_30 = param_3;
  local_2c = param_4;
  uStack_28 = param_3;
  uVar3 = FUN_0801126c(param_11 + 0x6c);
  iVar5 = 0;
  iVar7 = 0;
  while( true ) {
    local_2c = param_4;
    iVar4 = FUN_08012ee0(&local_30,&param_5);
    uVar6 = local_2c;
    if ((iVar4 == 0) || (iVar7 == param_10)) break;
    uVar2 = FUN_08012e9c(&local_30);
    uVar6 = local_2c;
    iVar4 = FUN_08010d04(uVar3,uVar2,0x2a);
    if (9 < (iVar4 - 0x30U & 0xff)) break;
    iVar5 = iVar5 * 10 + (iVar4 - 0x30U);
    if (param_9 < iVar5) break;
    FUN_08010bc6(local_30);
    iVar7 = iVar7 + 1;
    param_4 = 0xffffffff;
  }
  if (((iVar7 == 0) || (iVar5 < param_8)) || (param_9 < iVar5)) {
    *puVar1 = *puVar1 | 4;
  }
  else {
    *param_7 = iVar5;
  }
  *param_1 = local_30;
  param_1[1] = uVar6;
  return param_1;
}

