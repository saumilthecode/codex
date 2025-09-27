
void FUN_08009764(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 local_14;
  int iStack_10;
  
  local_14 = param_2;
  iStack_10 = param_3;
  uVar1 = FUN_08018bcc(param_2);
  *(undefined4 *)(param_3 + 0x24) = uVar1;
  uVar1 = FUN_08018bd2(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x14) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined1 *)(param_3 + 0x124) = 1;
  *(undefined4 *)(param_3 + 0x28) = uVar1;
  FUN_08018bd8(&local_14,param_2);
  uVar1 = FUN_080091d0(param_3 + 8,&local_14);
  *(undefined4 *)(param_3 + 0xc) = uVar1;
  FUN_080091fc(local_14);
  FUN_08018be6(&local_14,param_2);
  uVar1 = FUN_08009254(param_3 + 0x14,&local_14);
  *(undefined4 *)(param_3 + 0x18) = uVar1;
  FUN_08009134(local_14);
  FUN_08018bf4(&local_14,param_2);
  uVar1 = FUN_08009254(param_3 + 0x1c,&local_14);
  *(undefined4 *)(param_3 + 0x20) = uVar1;
  FUN_08009134(local_14);
  return;
}

