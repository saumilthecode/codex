
int FUN_08021268(int *param_1,undefined4 *param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  
  FUN_08021240(param_1,param_4,param_3,param_4,param_4);
  while( true ) {
    if ((param_1[1] == *param_1) || (puVar3 = (uint *)*param_2, (uint *)param_2[1] == puVar3)) {
      iVar2 = param_1[1] - *param_1;
      if (iVar2 != 0) {
        iVar2 = 1;
      }
      return iVar2;
    }
    uVar1 = FUN_08020d42(param_1,param_3);
    if (uVar1 == 0xfffffffe) {
      return 1;
    }
    if (param_3 < uVar1) break;
    *param_2 = puVar3 + 1;
    *puVar3 = uVar1;
  }
  return 2;
}

