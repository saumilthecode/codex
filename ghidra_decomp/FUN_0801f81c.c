
undefined1
FUN_0801f81c(undefined4 param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4,
            undefined4 *param_5,uint param_6,uint param_7,uint *param_8)

{
  undefined1 uVar1;
  int iVar2;
  uint uVar3;
  undefined1 auStack_34 [4];
  undefined4 local_30;
  undefined4 uStack_2c;
  
  local_30 = *param_2;
  uStack_2c = param_2[1];
  iVar2 = FUN_08028508();
  iVar2 = iVar2 * ((int)param_4 - (int)param_3 >> 2);
  if (iVar2 - (param_7 - param_6) == 0 || iVar2 < (int)(param_7 - param_6)) {
    while (param_3 < param_4) {
      iVar2 = FUN_08025914(param_6,*param_3,&local_30);
      if (iVar2 == -1) goto LAB_0801f8ce;
      param_6 = param_6 + iVar2;
      *param_2 = local_30;
      param_2[1] = uStack_2c;
      param_3 = param_3 + 1;
    }
  }
  else {
    for (; (param_3 < param_4 && (param_6 < param_7)); param_6 = param_6 + uVar3) {
      uVar3 = FUN_08025914(auStack_34,*param_3,&local_30);
      if (uVar3 == 0xffffffff) goto LAB_0801f8ce;
      if (param_7 - param_6 < uVar3) {
        uVar1 = 1;
        goto LAB_0801f8be;
      }
      FUN_08028666(param_6,auStack_34,uVar3);
      *param_2 = local_30;
      param_2[1] = uStack_2c;
      param_3 = param_3 + 1;
    }
  }
  uVar1 = param_3 < param_4;
LAB_0801f8be:
  *param_5 = param_3;
  *param_8 = param_6;
  return uVar1;
LAB_0801f8ce:
  uVar1 = 2;
  goto LAB_0801f8be;
}

