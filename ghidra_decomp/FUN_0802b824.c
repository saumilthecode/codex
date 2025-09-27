
int FUN_0802b824(int param_1,int param_2,char param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  code *pcVar5;
  undefined4 uVar6;
  undefined4 local_3f8;
  undefined4 local_3f4;
  undefined4 uStack_3f0;
  undefined4 uStack_3ec;
  undefined4 uStack_3e8;
  undefined4 local_3e4;
  undefined4 uStack_3e0;
  undefined4 uStack_3dc;
  undefined4 uStack_3d8;
  undefined4 local_3d4;
  undefined4 uStack_3d0;
  undefined4 uStack_3cc;
  undefined4 uStack_3c8;
  undefined4 local_3c4;
  undefined4 local_3c0;
  undefined4 uStack_3bc;
  undefined4 local_3b8;
  undefined4 local_3b0;
  undefined1 auStack_210 [56];
  undefined4 local_1d8;
  
  pcVar5 = *(code **)(param_1 + 0xc);
  uVar6 = *(undefined4 *)(param_1 + 0x18);
  local_3f4 = *(undefined4 *)(param_2 + 4);
  uStack_3f0 = *(undefined4 *)(param_2 + 8);
  uStack_3ec = *(undefined4 *)(param_2 + 0xc);
  uStack_3e8 = *(undefined4 *)(param_2 + 0x10);
  local_3e4 = *(undefined4 *)(param_2 + 0x14);
  uStack_3e0 = *(undefined4 *)(param_2 + 0x18);
  uStack_3dc = *(undefined4 *)(param_2 + 0x1c);
  uStack_3d8 = *(undefined4 *)(param_2 + 0x20);
  local_3d4 = *(undefined4 *)(param_2 + 0x24);
  uStack_3d0 = *(undefined4 *)(param_2 + 0x28);
  uStack_3cc = *(undefined4 *)(param_2 + 0x2c);
  uStack_3c8 = *(undefined4 *)(param_2 + 0x30);
  local_3c4 = *(undefined4 *)(param_2 + 0x34);
  local_3c0 = *(undefined4 *)(param_2 + 0x38);
  uStack_3bc = *(undefined4 *)(param_2 + 0x3c);
  local_3b8 = *(undefined4 *)(param_2 + 0x40);
  iVar3 = 0;
  local_3f8 = 0;
  do {
    iVar1 = FUN_0802b704(param_1,local_3b8);
    bVar4 = param_3 + 9;
    if (iVar1 != 0) goto LAB_0802b8ce;
    *(undefined4 *)(param_1 + 0x14) = local_3b8;
    FUN_08028666(auStack_210,&local_3f8,0x1e8);
    iVar3 = (**(code **)(param_1 + 0x10))(bVar4,param_1,auStack_210);
    local_3b0 = local_1d8;
    while( true ) {
      iVar2 = (*pcVar5)(1,bVar4,param_1,param_1,&local_3f8,uVar6);
      if (iVar2 != 0) {
        return 9;
      }
      if (iVar1 != 0) {
        return iVar1;
      }
      FUN_08028666(&local_3f8,auStack_210,0x1e8);
      param_3 = '\0';
      if (iVar3 == 8) break;
      if (iVar3 != 7) {
        return 9;
      }
      FUN_0802b7e8(0,local_3b8);
      FUN_080069b0(&local_3f4);
      bVar4 = 0;
LAB_0802b8ce:
      bVar4 = bVar4 | 0x10;
      local_3b0 = local_3c0;
    }
  } while( true );
}

