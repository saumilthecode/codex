
void FUN_0800bc9c(int *param_1,int param_2,int param_3)

{
  int iVar1;
  uint local_14;
  
  local_14 = param_3 - param_2;
  if (0xf < local_14) {
    iVar1 = FUN_08017ce4(param_1,&local_14,0,local_14,param_1);
    *param_1 = iVar1;
    param_1[2] = local_14;
  }
  FUN_08017de8(*param_1,param_2,param_3);
  param_1[1] = local_14;
  *(undefined1 *)(*param_1 + local_14) = 0;
  return;
}

