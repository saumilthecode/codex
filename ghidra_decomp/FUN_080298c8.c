
int FUN_080298c8(undefined4 param_1,int param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  
  if (param_2 != 0) {
    if (param_3 == 0) {
      FUN_08028790();
      iVar1 = 0;
    }
    else {
      uVar2 = FUN_0802afb8();
      if (((uVar2 < param_3) || (iVar1 = param_2, param_3 <= uVar2 >> 1)) &&
         (iVar1 = FUN_08024a18(param_1,param_3), iVar1 != 0)) {
        if (uVar2 <= param_3) {
          param_3 = uVar2;
        }
        FUN_08028666(iVar1,param_2,param_3);
        FUN_08028790(param_1,param_2);
      }
    }
    return iVar1;
  }
  iVar1 = FUN_08024a18(param_1,param_3);
  return iVar1;
}

