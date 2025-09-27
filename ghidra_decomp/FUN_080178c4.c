
int * FUN_080178c4(int *param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int *local_20;
  undefined4 uStack_1c;
  
  local_20 = param_1;
  uStack_1c = param_2;
  FUN_08017700(&local_20,param_1);
  if (((uint)local_20 & 0xff) != 0) {
    iVar2 = *(int *)((int)param_1 + *(int *)(*param_1 + -0xc) + 8);
    if (param_3 < iVar2) {
      uVar1 = *(uint *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0xc) & 0xb0;
      if (uVar1 != 0x20) {
        FUN_08017854(param_1,iVar2 - param_3);
      }
      if (((*(int *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x14) == 0) &&
          (FUN_08017898(param_1,param_2,param_3), uVar1 == 0x20)) &&
         (*(int *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x14) == 0)) {
        FUN_08017854(param_1,iVar2 - param_3);
      }
    }
    else {
      FUN_08017898(param_1,param_2,param_3);
    }
    *(undefined4 *)((int)param_1 + *(int *)(*param_1 + -0xc) + 8) = 0;
  }
  FUN_0801767c(&local_20);
  return param_1;
}

