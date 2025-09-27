
undefined1
FUN_0801f8d2(undefined4 param_1,undefined4 *param_2,uint param_3,uint param_4,uint *param_5,
            undefined4 *param_6,undefined4 *param_7,undefined4 *param_8)

{
  int iVar1;
  undefined1 uVar2;
  undefined4 local_28;
  undefined4 uStack_24;
  uint uStack_20;
  
  local_28 = *param_2;
  uStack_24 = param_2[1];
  uStack_20 = param_3;
  for (; (param_3 < param_4 && (param_6 < param_7)); param_6 = param_6 + 1) {
    iVar1 = FUN_080258cc(param_6,param_3,param_4 - param_3,&local_28);
    if (iVar1 == -1) {
      uVar2 = 2;
      goto LAB_0801f928;
    }
    if (iVar1 == -2) {
      uVar2 = 1;
      goto LAB_0801f928;
    }
    if (iVar1 == 0) {
      *param_6 = 0;
      iVar1 = 1;
    }
    *param_2 = local_28;
    param_2[1] = uStack_24;
    param_3 = param_3 + iVar1;
  }
  uVar2 = param_3 < param_4;
LAB_0801f928:
  *param_5 = param_3;
  *param_8 = param_6;
  return uVar2;
}

