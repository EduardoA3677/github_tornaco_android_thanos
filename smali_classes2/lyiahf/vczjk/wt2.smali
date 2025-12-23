.class public abstract Llyiahf/vczjk/wt2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/16 v0, 0x10

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/wt2;->OooO00o:F

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 15

    move-object/from16 v9, p5

    check-cast v9, Llyiahf/vczjk/zf1;

    const v0, -0x37cc24b5

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    or-int/lit8 v0, p6, 0x6

    move-object/from16 v6, p4

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/16 v1, 0x4000

    goto :goto_0

    :cond_0
    const/16 v1, 0x2000

    :goto_0
    or-int/2addr v0, v1

    and-int/lit16 v1, v0, 0x2493

    const/16 v2, 0x2492

    if-ne v1, v2, :cond_2

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v2, p0

    move/from16 v12, p1

    move-object/from16 v13, p2

    move-object/from16 v14, p3

    goto :goto_2

    :cond_2
    :goto_1
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    new-instance p0, Llyiahf/vczjk/vt2;

    move/from16 v12, p1

    move-object/from16 v13, p2

    move-object/from16 v14, p3

    invoke-direct {p0, v14, v12, v13}, Llyiahf/vczjk/vt2;-><init>(Llyiahf/vczjk/a91;ZLlyiahf/vczjk/a91;)V

    const v2, 0x79823489

    invoke-static {v2, p0, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    shr-int/lit8 p0, v0, 0xc

    and-int/lit8 p0, p0, 0xe

    const v0, 0xc00030

    or-int v10, p0, v0

    const-wide/16 v5, 0x0

    const/4 v7, 0x0

    const/4 v2, 0x0

    const-wide/16 v3, 0x0

    const/16 v11, 0x7c

    move-object/from16 v0, p4

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/v33;->OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/h33;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    move-object v2, v1

    :goto_2
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p0

    if-eqz p0, :cond_3

    new-instance v1, Llyiahf/vczjk/ut2;

    move-object/from16 v6, p4

    move/from16 v7, p6

    move v3, v12

    move-object v4, v13

    move-object v5, v14

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/ut2;-><init>(Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;I)V

    iput-object v1, p0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method
