
undefined4 FUN_0800058c(uint param_1)

{
  byte *pbVar1;
  int iVar2;
  
  pbVar1 = DAT_080005cc;
  iVar2 = FUN_08000870(*DAT_080005c8 / (1000 / *DAT_080005cc));
  if ((iVar2 == 0) && (param_1 < 0x10)) {
    FUN_08000794(0xffffffff,param_1,0);
    *(uint *)(pbVar1 + 4) = param_1;
    return 0;
  }
  return 1;
}

