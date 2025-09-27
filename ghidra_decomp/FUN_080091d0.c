
int FUN_080091d0(int *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_0800914a(*param_2);
  iVar1 = (int)uVar3;
  iVar2 = thunk_FUN_08008466(iVar1 + 1);
  FUN_0800a6c0((int)((ulonglong)uVar3 >> 0x20),iVar2,iVar1,0,param_4);
  *(undefined1 *)(iVar2 + iVar1) = 0;
  *param_1 = iVar2;
  return iVar1;
}

