
uint FUN_08020ed6(undefined4 *param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  pbVar4 = (byte *)*param_1;
  iVar3 = (int)param_1[1] - (int)pbVar4;
  if ((byte *)param_1[1] == pbVar4) {
    return 0xfffffffe;
  }
  uVar1 = (uint)*pbVar4;
  if (uVar1 < 0x80) {
    pbVar4 = pbVar4 + 1;
LAB_08020eea:
    *param_1 = pbVar4;
  }
  else {
    if (0xc1 < uVar1) {
      if (uVar1 < 0xe0) {
        if (iVar3 == 1) {
          return 0xfffffffe;
        }
        if ((pbVar4[1] & 0xc0) == 0x80) {
          uVar1 = (pbVar4[1] - 0x3080) + uVar1 * 0x40;
          pbVar4 = pbVar4 + 2;
          goto LAB_08020eea;
        }
      }
      else if (uVar1 < 0xf0) {
        if (iVar3 == 1) {
          return 0xfffffffe;
        }
        uVar2 = (uint)pbVar4[1];
        if ((uVar2 & 0xc0) == 0x80) {
          if (uVar1 == 0xe0) {
            if (0x9f < uVar2) {
LAB_08020f38:
              if (iVar3 == 2) {
                return 0xfffffffe;
              }
              if ((pbVar4[2] & 0xc0) == 0x80) {
                uVar1 = (pbVar4[2] - 0xe2080) + uVar1 * 0x1000 + uVar2 * 0x40;
                pbVar4 = pbVar4 + 3;
                goto LAB_08020eea;
              }
            }
          }
          else if ((uVar1 != 0xed) || (uVar2 < 0xa0)) goto LAB_08020f38;
        }
      }
      else if ((uVar1 < 0xf5) && (param_2 != 0xffff)) {
        if (iVar3 == 1) {
          return 0xfffffffe;
        }
        uVar2 = (uint)pbVar4[1];
        if ((uVar2 & 0xc0) == 0x80) {
          if (uVar1 == 0xf0) {
            if (0x8f < uVar2) {
LAB_08020f7a:
              if (iVar3 == 2) {
                return 0xfffffffe;
              }
              if ((pbVar4[2] & 0xc0) == 0x80) {
                if (iVar3 == 3) {
                  return 0xfffffffe;
                }
                if ((pbVar4[3] & 0xc0) == 0x80) {
                  uVar1 = pbVar4[3] + 0xfc37df80 + uVar1 * 0x40000 + uVar2 * 0x1000 +
                          (uint)pbVar4[2] * 0x40;
                  if (0x10ffff < uVar1) {
                    return uVar1;
                  }
                  pbVar4 = pbVar4 + 4;
                  goto LAB_08020eea;
                }
              }
            }
          }
          else if ((uVar1 != 0xf4) || (uVar2 < 0x90)) goto LAB_08020f7a;
        }
      }
    }
    uVar1 = 0xffffffff;
  }
  return uVar1;
}

