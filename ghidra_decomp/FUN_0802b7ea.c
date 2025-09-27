
int FUN_0802b7ea(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  code *pcVar6;
  undefined4 uVar7;
  undefined8 uVar8;
  undefined4 uStack_408;
  undefined4 uStack_404;
  undefined4 uStack_400;
  undefined4 uStack_3fc;
  undefined4 uStack_3f8;
  undefined4 uStack_3f4;
  undefined4 uStack_3f0;
  undefined4 uStack_3ec;
  undefined4 uStack_3e8;
  undefined4 uStack_3e4;
  undefined4 uStack_3e0;
  undefined4 uStack_3dc;
  undefined4 uStack_3d8;
  undefined4 uStack_3d4;
  undefined4 uStack_3d0;
  undefined4 uStack_3cc;
  undefined4 uStack_3c8;
  undefined4 uStack_3c0;
  undefined1 auStack_220 [56];
  undefined4 uStack_1e8;
  int iStack_34;
  int iStack_30;
  undefined4 uStack_2c;
  
  do {
    iVar1 = FUN_0802b704(param_1,*(undefined4 *)(param_2 + 0x40));
    if (iVar1 != 0) goto LAB_0802b7fc;
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x40);
    iVar1 = param_2;
    iVar2 = (**(code **)(param_1 + 0x10))(1,param_1,param_2);
  } while (iVar2 == 8);
  if (iVar2 == 7) {
    FUN_0802b7e8(0,*(undefined4 *)(param_2 + 0x40));
    uVar8 = FUN_080069b0(param_2 + 4);
    iVar4 = (int)((ulonglong)uVar8 >> 0x20);
    iVar2 = (int)uVar8;
    pcVar6 = *(code **)(iVar2 + 0xc);
    uVar7 = *(undefined4 *)(iVar2 + 0x18);
    uStack_404 = *(undefined4 *)(iVar4 + 4);
    uStack_400 = *(undefined4 *)(iVar4 + 8);
    uStack_3fc = *(undefined4 *)(iVar4 + 0xc);
    uStack_3f8 = *(undefined4 *)(iVar4 + 0x10);
    uStack_3f4 = *(undefined4 *)(iVar4 + 0x14);
    uStack_3f0 = *(undefined4 *)(iVar4 + 0x18);
    uStack_3ec = *(undefined4 *)(iVar4 + 0x1c);
    uStack_3e8 = *(undefined4 *)(iVar4 + 0x20);
    uStack_3e4 = *(undefined4 *)(iVar4 + 0x24);
    uStack_3e0 = *(undefined4 *)(iVar4 + 0x28);
    uStack_3dc = *(undefined4 *)(iVar4 + 0x2c);
    uStack_3d8 = *(undefined4 *)(iVar4 + 0x30);
    uStack_3d4 = *(undefined4 *)(iVar4 + 0x34);
    uStack_3d0 = *(undefined4 *)(iVar4 + 0x38);
    uStack_3cc = *(undefined4 *)(iVar4 + 0x3c);
    uStack_3c8 = *(undefined4 *)(iVar4 + 0x40);
    iVar4 = 0;
    uStack_408 = 0;
    uStack_2c = 0;
    iStack_34 = param_2;
    iStack_30 = param_1;
    do {
      iVar3 = FUN_0802b704(iVar2,uStack_3c8);
      uVar5 = iVar1 + 9U & 0xff;
      if (iVar3 != 0) goto LAB_0802b8ce;
      *(undefined4 *)(iVar2 + 0x14) = uStack_3c8;
      FUN_08028666(auStack_220,&uStack_408,0x1e8);
      iVar4 = (**(code **)(iVar2 + 0x10))(uVar5,iVar2,auStack_220);
      uStack_3c0 = uStack_1e8;
      while( true ) {
        iVar1 = (*pcVar6)(1,uVar5,iVar2,iVar2,&uStack_408,uVar7);
        if (iVar1 != 0) {
          return 9;
        }
        if (iVar3 != 0) {
          return iVar3;
        }
        FUN_08028666(&uStack_408,auStack_220,0x1e8);
        iVar1 = 0;
        if (iVar4 == 8) break;
        if (iVar4 != 7) {
          return 9;
        }
        FUN_0802b7e8(0,uStack_3c8);
        FUN_080069b0(&uStack_404);
        uVar5 = 0;
LAB_0802b8ce:
        uVar5 = uVar5 | 0x10;
        uStack_3c0 = uStack_3d0;
      }
    } while( true );
  }
LAB_0802b7fc:
                    /* WARNING: Subroutine does not return */
  FUN_080249a4();
}

