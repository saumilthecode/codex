
void FUN_080096ea(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined1 uVar1;
  undefined4 uVar2;
  undefined4 local_14;
  int iStack_10;
  
  local_14 = param_2;
  iStack_10 = param_3;
  uVar1 = FUN_08010fac(param_2);
  *(undefined1 *)(param_3 + 0x24) = uVar1;
  uVar1 = FUN_08010fb2(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x14) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined1 *)(param_3 + 100) = 1;
  *(undefined1 *)(param_3 + 0x25) = uVar1;
  FUN_08010fb8(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 8,&local_14);
  *(undefined4 *)(param_3 + 0xc) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010fc6(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x14,&local_14);
  *(undefined4 *)(param_3 + 0x18) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010fd4(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x1c,&local_14);
  *(undefined4 *)(param_3 + 0x20) = uVar2;
  FUN_080091fc(local_14);
  return;
}

