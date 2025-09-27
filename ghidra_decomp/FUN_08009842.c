
void FUN_08009842(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined1 uVar1;
  undefined4 uVar2;
  undefined4 local_14;
  int iStack_10;
  
  local_14 = param_2;
  iStack_10 = param_3;
  uVar1 = FUN_08010f26(param_2);
  *(undefined1 *)(param_3 + 0x11) = uVar1;
  uVar1 = FUN_08010f2c(param_2);
  *(undefined1 *)(param_3 + 0x12) = uVar1;
  uVar2 = FUN_08010f6a(param_2);
  *(undefined4 *)(param_3 + 8) = 0;
  *(undefined4 *)(param_3 + 0x14) = 0;
  *(undefined4 *)(param_3 + 0x1c) = 0;
  *(undefined4 *)(param_3 + 0x24) = 0;
  *(undefined1 *)(param_3 + 0x43) = 1;
  *(undefined4 *)(param_3 + 0x2c) = uVar2;
  FUN_08010f32(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 8,&local_14);
  *(undefined4 *)(param_3 + 0xc) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010f40(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x14,&local_14);
  *(undefined4 *)(param_3 + 0x18) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010f4e(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x1c,&local_14);
  *(undefined4 *)(param_3 + 0x20) = uVar2;
  FUN_080091fc(local_14);
  FUN_08010f5c(&local_14,param_2);
  uVar2 = FUN_080091d0(param_3 + 0x24,&local_14);
  *(undefined4 *)(param_3 + 0x28) = uVar2;
  FUN_080091fc(local_14);
  uVar2 = FUN_08010f70(param_2);
  *(undefined4 *)(param_3 + 0x30) = uVar2;
  uVar2 = FUN_08010f7a(param_2);
  *(undefined4 *)(param_3 + 0x34) = uVar2;
  return;
}

