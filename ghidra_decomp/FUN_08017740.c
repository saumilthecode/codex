
int * FUN_08017740(int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int *local_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  
  local_18 = param_1;
  uStack_14 = param_2;
  uStack_10 = param_3;
  FUN_08017700(&local_18,param_1);
  if (((char)local_18 != '\0') &&
     (iVar1 = FUN_08017c78(*(undefined4 *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x78),param_2)
     , iVar1 == -1)) {
    FUN_08010584(*(int *)(*param_1 + -0xc) + (int)param_1,1);
  }
  FUN_0801767c(&local_18);
  return param_1;
}

