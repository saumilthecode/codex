
void FUN_080290b8(undefined4 param_1,int param_2,int param_3,int param_4,undefined4 param_5)

{
  int iVar1;
  int extraout_r1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  byte *pbVar5;
  int iVar6;
  
  iVar3 = (param_4 + 8) / 9;
  iVar1 = 0;
  iVar2 = 1;
  iVar6 = param_4;
  do {
    if (iVar3 <= iVar2) {
      iVar2 = FUN_08028f6c(param_1,iVar1);
      if (iVar2 != 0) {
        *(undefined4 *)(iVar2 + 0x14) = param_5;
        *(undefined4 *)(iVar2 + 0x10) = 1;
        if (param_3 < 10) {
          pbVar4 = (byte *)(param_2 + 10);
          param_3 = 9;
        }
        else {
          pbVar4 = (byte *)(param_2 + 9);
          do {
            pbVar5 = pbVar4 + 1;
            iVar2 = FUN_0802902c(param_1,iVar2,10,*pbVar4 - 0x30,iVar6);
            pbVar4 = pbVar5;
          } while (pbVar5 != (byte *)(param_2 + param_3));
          pbVar4 = (byte *)(param_2 + 9) + param_3 + -8;
        }
        param_3 = param_3 - (int)pbVar4;
        for (; (int)(pbVar4 + param_3) < param_4; pbVar4 = pbVar4 + 1) {
          iVar2 = FUN_0802902c(param_1,iVar2,10,*pbVar4 - 0x30,iVar6);
        }
        return;
      }
      iVar3 = DAT_08029144;
      FUN_08028754(DAT_08029148,0xd3);
      iVar1 = extraout_r1;
    }
    iVar2 = iVar2 << 1;
    iVar1 = iVar1 + 1;
  } while( true );
}

