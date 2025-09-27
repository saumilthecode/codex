
void FUN_08028754(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  
  iVar1 = DAT_0802878c;
  iVar2 = DAT_0802878c;
  if (param_3 != 0) {
    iVar1 = DAT_08028784;
    iVar2 = param_3;
  }
  FUN_0802a7dc(*(undefined4 *)(*DAT_08028780 + 0xc),DAT_08028788,param_4,param_1,param_2,iVar1,iVar2
               ,param_4);
                    /* WARNING: Subroutine does not return */
  FUN_080249a4();
}

