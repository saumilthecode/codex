
undefined4 FUN_0802b8e4(int param_1,int param_2)

{
  int iVar1;
  undefined4 local_200;
  undefined4 local_1fc;
  undefined4 uStack_1f8;
  undefined4 uStack_1f4;
  undefined4 uStack_1f0;
  undefined4 local_1ec;
  undefined4 uStack_1e8;
  undefined4 uStack_1e4;
  undefined4 uStack_1e0;
  undefined4 local_1dc;
  undefined4 uStack_1d8;
  undefined4 uStack_1d4;
  undefined4 uStack_1d0;
  undefined4 local_1cc;
  undefined4 uStack_1c8;
  undefined4 uStack_1c4;
  undefined4 local_1c0;
  
  *(undefined4 *)(param_2 + 0x40) = *(undefined4 *)(param_2 + 0x3c);
  local_1fc = *(undefined4 *)(param_2 + 4);
  uStack_1f8 = *(undefined4 *)(param_2 + 8);
  uStack_1f4 = *(undefined4 *)(param_2 + 0xc);
  uStack_1f0 = *(undefined4 *)(param_2 + 0x10);
  local_1ec = *(undefined4 *)(param_2 + 0x14);
  uStack_1e8 = *(undefined4 *)(param_2 + 0x18);
  uStack_1e4 = *(undefined4 *)(param_2 + 0x1c);
  uStack_1e0 = *(undefined4 *)(param_2 + 0x20);
  local_1dc = *(undefined4 *)(param_2 + 0x24);
  uStack_1d8 = *(undefined4 *)(param_2 + 0x28);
  uStack_1d4 = *(undefined4 *)(param_2 + 0x2c);
  uStack_1d0 = *(undefined4 *)(param_2 + 0x30);
  local_1cc = *(undefined4 *)(param_2 + 0x34);
  uStack_1c8 = *(undefined4 *)(param_2 + 0x38);
  uStack_1c4 = *(undefined4 *)(param_2 + 0x3c);
  local_1c0 = *(undefined4 *)(param_2 + 0x40);
  local_200 = 0xffffffff;
  do {
    iVar1 = FUN_0802b704(param_1,local_1c0);
    if (iVar1 != 0) {
      return 9;
    }
    iVar1 = (**(code **)(param_1 + 0x10))(0,param_1,&local_200);
  } while (iVar1 == 8);
  FUN_0802b790(&local_200);
  if (iVar1 == 6) {
    FUN_0802b7ea(param_1,param_2);
  }
  return 9;
}

