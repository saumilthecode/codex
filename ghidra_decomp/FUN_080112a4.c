
void FUN_080112a4(int param_1,undefined4 param_2)

{
  undefined1 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char *pcVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24 [2];
  
  uVar2 = FUN_08011294(param_2);
  FUN_08010fb8(&local_2c,uVar2);
  uVar3 = FUN_08010c1a(local_2c);
  *(undefined4 *)(param_1 + 0xc) = uVar3;
  pcVar4 = (char *)thunk_FUN_08008466();
  FUN_0800a6c0(&local_2c,pcVar4,*(undefined4 *)(param_1 + 0xc),0);
  iVar6 = *(int *)(param_1 + 0xc);
  if (iVar6 != 0) {
    if (*pcVar4 < '\x01') {
      iVar6 = 0;
    }
    else {
      iVar6 = 1;
    }
  }
  *(char *)(param_1 + 0x10) = (char)iVar6;
  FUN_08010fc6(&local_28,uVar2);
  uVar3 = FUN_08010c1a(local_28);
  *(undefined4 *)(param_1 + 0x18) = uVar3;
  uVar3 = thunk_FUN_08008466();
  FUN_0800a6c0(&local_28,uVar3,*(undefined4 *)(param_1 + 0x18),0);
  FUN_08010fd4(local_24,uVar2);
  uVar5 = FUN_08010c1a(local_24[0]);
  *(undefined4 *)(param_1 + 0x20) = uVar5;
  uVar5 = thunk_FUN_08008466();
  FUN_0800a6c0(local_24,uVar5,*(undefined4 *)(param_1 + 0x20),0);
  uVar1 = FUN_08010fac(uVar2);
  *(undefined1 *)(param_1 + 0x24) = uVar1;
  uVar1 = FUN_08010fb2(uVar2);
  *(undefined1 *)(param_1 + 0x25) = uVar1;
  uVar2 = FUN_0801126c(param_2);
  FUN_08010c84(uVar2,*DAT_08011394,*DAT_08011394 + 0x24,param_1 + 0x26);
  FUN_08010c84(uVar2,*DAT_08011398,*DAT_08011398 + 0x1a,param_1 + 0x4a);
  *(undefined1 *)(param_1 + 100) = 1;
  *(char **)(param_1 + 8) = pcVar4;
  *(undefined4 *)(param_1 + 0x14) = uVar3;
  *(undefined4 *)(param_1 + 0x1c) = uVar5;
  FUN_08010c74(local_24[0]);
  FUN_08010c74(local_28);
  FUN_08010c74(local_2c);
  return;
}

