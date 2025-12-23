.class public final Llyiahf/vczjk/vk0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:F

.field public final OooO0O0:F

.field public final OooO0OO:F

.field public final OooO0Oo:F

.field public final OooO0o0:F


# direct methods
.method public constructor <init>(FFFFF)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/vk0;->OooO00o:F

    iput p2, p0, Llyiahf/vczjk/vk0;->OooO0O0:F

    iput p3, p0, Llyiahf/vczjk/vk0;->OooO0OO:F

    iput p4, p0, Llyiahf/vczjk/vk0;->OooO0Oo:F

    iput p5, p0, Llyiahf/vczjk/vk0;->OooO0o0:F

    return-void
.end method


# virtual methods
.method public final OooO00o(ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/xl;
    .locals 14

    move-object/from16 v0, p2

    move/from16 v1, p4

    move-object/from16 v7, p3

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v5, :cond_0

    new-instance v2, Llyiahf/vczjk/tw8;

    invoke-direct {v2}, Llyiahf/vczjk/tw8;-><init>()V

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_0
    check-cast v2, Llyiahf/vczjk/tw8;

    and-int/lit8 v6, v1, 0x70

    xor-int/lit8 v6, v6, 0x30

    const/16 v8, 0x20

    const/4 v9, 0x1

    const/4 v10, 0x0

    if-le v6, v8, :cond_1

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_2

    :cond_1
    and-int/lit8 v6, v1, 0x30

    if-ne v6, v8, :cond_3

    :cond_2
    move v6, v9

    goto :goto_0

    :cond_3
    move v6, v10

    :goto_0
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    const/4 v11, 0x0

    if-nez v6, :cond_4

    if-ne v8, v5, :cond_5

    :cond_4
    new-instance v8, Llyiahf/vczjk/tk0;

    invoke-direct {v8, v0, v2, v11}, Llyiahf/vczjk/tk0;-><init>(Llyiahf/vczjk/n24;Llyiahf/vczjk/tw8;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v7, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v8, Llyiahf/vczjk/ze3;

    invoke-static {v0, v7, v8}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v2}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/j24;

    if-nez p1, :cond_6

    iget v2, p0, Llyiahf/vczjk/vk0;->OooO0o0:F

    goto :goto_1

    :cond_6
    instance-of v2, v0, Llyiahf/vczjk/q37;

    if-eqz v2, :cond_7

    iget v2, p0, Llyiahf/vczjk/vk0;->OooO0O0:F

    goto :goto_1

    :cond_7
    instance-of v2, v0, Llyiahf/vczjk/wo3;

    if-eqz v2, :cond_8

    iget v2, p0, Llyiahf/vczjk/vk0;->OooO0Oo:F

    goto :goto_1

    :cond_8
    instance-of v2, v0, Llyiahf/vczjk/g83;

    if-eqz v2, :cond_9

    iget v2, p0, Llyiahf/vczjk/vk0;->OooO0OO:F

    goto :goto_1

    :cond_9
    iget v2, p0, Llyiahf/vczjk/vk0;->OooO00o:F

    :goto_1
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v5, :cond_a

    new-instance v6, Llyiahf/vczjk/gi;

    new-instance v8, Llyiahf/vczjk/wd2;

    invoke-direct {v8, v2}, Llyiahf/vczjk/wd2;-><init>(F)V

    sget-object v12, Llyiahf/vczjk/gda;->OooO0OO:Llyiahf/vczjk/n1a;

    const/16 v13, 0xc

    invoke-direct {v6, v8, v12, v11, v13}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v6, Llyiahf/vczjk/gi;

    new-instance v8, Llyiahf/vczjk/wd2;

    invoke-direct {v8, v2}, Llyiahf/vczjk/wd2;-><init>(F)V

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v12

    or-int/2addr v11, v12

    and-int/lit8 v12, v1, 0xe

    xor-int/lit8 v12, v12, 0x6

    const/4 v13, 0x4

    if-le v12, v13, :cond_b

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v12

    if-nez v12, :cond_c

    :cond_b
    and-int/lit8 v12, v1, 0x6

    if-ne v12, v13, :cond_d

    :cond_c
    move v12, v9

    goto :goto_2

    :cond_d
    move v12, v10

    :goto_2
    or-int/2addr v11, v12

    and-int/lit16 v12, v1, 0x380

    xor-int/lit16 v12, v12, 0x180

    const/16 v13, 0x100

    if-le v12, v13, :cond_e

    invoke-virtual {v7, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_10

    :cond_e
    and-int/lit16 v1, v1, 0x180

    if-ne v1, v13, :cond_f

    goto :goto_3

    :cond_f
    move v9, v10

    :cond_10
    :goto_3
    or-int v1, v11, v9

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v1, v9

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v1, :cond_11

    if-ne v9, v5, :cond_12

    :cond_11
    move-object v5, v0

    goto :goto_4

    :cond_12
    move-object v1, v6

    goto :goto_5

    :goto_4
    new-instance v0, Llyiahf/vczjk/uk0;

    move-object v1, v6

    const/4 v6, 0x0

    move-object v4, p0

    move v3, p1

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/uk0;-><init>(Llyiahf/vczjk/gi;FZLlyiahf/vczjk/vk0;Llyiahf/vczjk/j24;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v9, v0

    :goto_5
    check-cast v9, Llyiahf/vczjk/ze3;

    invoke-static {v8, v7, v9}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v0, v1, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    if-eqz p1, :cond_7

    instance-of v0, p1, Llyiahf/vczjk/vk0;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    check-cast p1, Llyiahf/vczjk/vk0;

    iget v0, p1, Llyiahf/vczjk/vk0;->OooO00o:F

    iget v1, p0, Llyiahf/vczjk/vk0;->OooO00o:F

    invoke-static {v1, v0}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_1

    :cond_2
    iget v0, p0, Llyiahf/vczjk/vk0;->OooO0O0:F

    iget v1, p1, Llyiahf/vczjk/vk0;->OooO0O0:F

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_1

    :cond_3
    iget v0, p0, Llyiahf/vczjk/vk0;->OooO0OO:F

    iget v1, p1, Llyiahf/vczjk/vk0;->OooO0OO:F

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-nez v0, :cond_4

    goto :goto_1

    :cond_4
    iget v0, p0, Llyiahf/vczjk/vk0;->OooO0Oo:F

    iget v1, p1, Llyiahf/vczjk/vk0;->OooO0Oo:F

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-nez v0, :cond_5

    goto :goto_1

    :cond_5
    iget v0, p0, Llyiahf/vczjk/vk0;->OooO0o0:F

    iget p1, p1, Llyiahf/vczjk/vk0;->OooO0o0:F

    invoke-static {v0, p1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p1

    if-nez p1, :cond_6

    goto :goto_1

    :cond_6
    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_7
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget v0, p0, Llyiahf/vczjk/vk0;->OooO00o:F

    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget v2, p0, Llyiahf/vczjk/vk0;->OooO0O0:F

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v0

    iget v2, p0, Llyiahf/vczjk/vk0;->OooO0OO:F

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v0

    iget v2, p0, Llyiahf/vczjk/vk0;->OooO0Oo:F

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/vk0;->OooO0o0:F

    invoke-static {v1}, Ljava/lang/Float;->hashCode(F)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
