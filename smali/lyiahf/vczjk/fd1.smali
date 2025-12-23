.class public final Llyiahf/vczjk/fd1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/fd1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/fd1;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/rm4;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/fd1;->OooOOO0:Llyiahf/vczjk/fd1;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/jc9;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/wd2;

    iget v1, v1, Llyiahf/vczjk/wd2;->OooOOO0:F

    move-object/from16 v14, p3

    check-cast v14, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p4

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "s"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v2, 0xe

    if-nez v3, :cond_1

    move-object v3, v14

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v2

    goto :goto_1

    :cond_1
    move v3, v2

    :goto_1
    and-int/lit8 v2, v2, 0x70

    if-nez v2, :cond_3

    move-object v2, v14

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v2

    if-eqz v2, :cond_2

    const/16 v2, 0x20

    goto :goto_2

    :cond_2
    const/16 v2, 0x10

    :goto_2
    or-int/2addr v3, v2

    :cond_3
    and-int/lit16 v2, v3, 0x2db

    const/16 v4, 0x92

    if-ne v2, v4, :cond_5

    move-object v2, v14

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_5
    :goto_3
    and-int/lit8 v15, v3, 0x7e

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const-wide/16 v6, 0x0

    const-wide/16 v8, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/16 v16, 0x0

    const/16 v17, 0xffc

    invoke-static/range {v0 .. v17}, Llyiahf/vczjk/vb9;->OooO00o(Llyiahf/vczjk/jc9;FLlyiahf/vczjk/kl5;ZZZJJLlyiahf/vczjk/qj8;FZFLlyiahf/vczjk/rf1;III)V

    :goto_4
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
