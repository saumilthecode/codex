
int FUN_0801f94c(undefined4 param_1,undefined4 *param_2,uint param_3,uint param_4,int param_5)

{
  uint uVar1;
  int iVar2;
  undefined4 local_28;
  undefined4 uStack_24;
  uint uStack_20;
  
  local_28 = *param_2;
  uStack_24 = param_2[1];
  iVar2 = 0;
  uStack_20 = param_3;
  while (((param_3 < param_4 && (param_5 != 0)) &&
         (uVar1 = FUN_080258cc(0,param_3,param_4 - param_3,&local_28), uVar1 < 0xfffffffe))) {
    if (uVar1 == 0) {
      uVar1 = 1;
    }
    *param_2 = local_28;
    param_2[1] = uStack_24;
    param_3 = param_3 + uVar1;
    iVar2 = iVar2 + uVar1;
    param_5 = param_5 + -1;
  }
  return iVar2;
}

