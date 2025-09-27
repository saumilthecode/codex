
void FUN_08018ec4(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  char *pcVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24 [2];
  
  uVar1 = FUN_08018eb4(param_2);
  FUN_08018bd8(&local_2c,uVar1);
  uVar2 = FUN_08018910(local_2c);
  *(undefined4 *)(param_1 + 0xc) = uVar2;
  pcVar3 = (char *)thunk_FUN_08008466();
  FUN_0800a6c0(&local_2c,pcVar3,*(undefined4 *)(param_1 + 0xc),0);
  iVar7 = *(int *)(param_1 + 0xc);
  if (iVar7 != 0) {
    if (*pcVar3 < '\x01') {
      iVar7 = 0;
    }
    else {
      iVar7 = 1;
    }
  }
  *(char *)(param_1 + 0x10) = (char)iVar7;
  FUN_08018be6(&local_28,uVar1);
  uVar4 = FUN_080187c6(local_28);
  *(uint *)(param_1 + 0x18) = uVar4;
  if (uVar4 < 0x1fffffff) {
    iVar7 = uVar4 << 2;
  }
  else {
    iVar7 = -1;
  }
  uVar2 = thunk_FUN_08008466(iVar7);
  FUN_0800ad50(&local_28,uVar2,*(undefined4 *)(param_1 + 0x18),0);
  FUN_08018bf4(local_24,uVar1);
  uVar4 = FUN_080187c6(local_24[0]);
  *(uint *)(param_1 + 0x20) = uVar4;
  if (uVar4 < 0x1fffffff) {
    iVar7 = uVar4 << 2;
  }
  else {
    iVar7 = -1;
  }
  uVar5 = thunk_FUN_08008466(iVar7);
  FUN_0800ad50(local_24,uVar5,*(undefined4 *)(param_1 + 0x20),0);
  uVar6 = FUN_08018bcc(uVar1);
  *(undefined4 *)(param_1 + 0x24) = uVar6;
  uVar1 = FUN_08018bd2(uVar1);
  *(undefined4 *)(param_1 + 0x28) = uVar1;
  uVar1 = FUN_08018e8c(param_2);
  FUN_08018820(uVar1,*DAT_08018fcc,*DAT_08018fcc + 0x24,param_1 + 0x2c);
  FUN_08018820(uVar1,*DAT_08018fd0,*DAT_08018fd0 + 0x1a,param_1 + 0xbc);
  *(undefined1 *)(param_1 + 0x124) = 1;
  *(char **)(param_1 + 8) = pcVar3;
  *(undefined4 *)(param_1 + 0x14) = uVar2;
  *(undefined4 *)(param_1 + 0x1c) = uVar5;
  FUN_08018900(local_24[0]);
  FUN_08018900(local_28);
  FUN_08018950(local_2c);
  return;
}

