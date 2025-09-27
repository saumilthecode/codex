
int FUN_0800b742(int *param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 4);
  iVar1 = thunk_FUN_08008466(iVar2 + 1);
  FUN_08018148(param_2,iVar1,iVar2,0,param_4);
  *(undefined1 *)(iVar1 + iVar2) = 0;
  *param_1 = iVar1;
  return iVar2;
}

