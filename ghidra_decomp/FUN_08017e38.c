
void FUN_08017e38(int *param_1,int param_2,int param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int local_24;
  
  local_24 = (param_5 - param_3) + param_1[1];
  iVar3 = param_1[1] - (param_2 + param_3);
  uVar1 = FUN_08017e26();
  iVar2 = FUN_08017ce4(param_1,&local_24,uVar1);
  if (param_2 != 0) {
    FUN_08017d6c(iVar2,*param_1,param_2);
  }
  if ((param_4 != 0) && (param_5 != 0)) {
    FUN_08017d6c(iVar2 + param_2,param_4,param_5);
  }
  if (iVar3 != 0) {
    FUN_08017d6c(iVar2 + param_2 + param_5,*param_1 + param_2 + param_3,iVar3);
  }
  FUN_08006cec(param_1);
  *param_1 = iVar2;
  param_1[2] = local_24;
  return;
}

