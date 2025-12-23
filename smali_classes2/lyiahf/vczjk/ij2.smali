.class public final Llyiahf/vczjk/ij2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oj2;

.field public final synthetic OooOOO0:F

.field public final synthetic OooOOOO:Ljava/util/List;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/oj2;Ljava/util/List;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/ij2;->OooOOO0:F

    iput-object p2, p0, Llyiahf/vczjk/ij2;->OooOOO:Llyiahf/vczjk/oj2;

    iput-object p3, p0, Llyiahf/vczjk/ij2;->OooOOOO:Ljava/util/List;

    iput-object p4, p0, Llyiahf/vczjk/ij2;->OooOOOo:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget v3, v0, Llyiahf/vczjk/ij2;->OooOOO0:F

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/el8;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v2, v3}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v6

    iget-object v2, v0, Llyiahf/vczjk/ij2;->OooOOO:Llyiahf/vczjk/oj2;

    iget-object v3, v2, Llyiahf/vczjk/oj2;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    check-cast v1, Llyiahf/vczjk/zf1;

    const v3, 0x4c5de2

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v3, :cond_2

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v3, :cond_3

    :cond_2
    new-instance v5, Llyiahf/vczjk/w71;

    const/4 v3, 0x1

    invoke-direct {v5, v2, v3}, Llyiahf/vczjk/w71;-><init>(Llyiahf/vczjk/oj2;I)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v5, Llyiahf/vczjk/le3;

    const/4 v3, 0x0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v3, Llyiahf/vczjk/n6;

    iget-object v7, v0, Llyiahf/vczjk/ij2;->OooOOOO:Ljava/util/List;

    iget-object v8, v0, Llyiahf/vczjk/ij2;->OooOOOo:Llyiahf/vczjk/oe3;

    const/16 v9, 0xa

    invoke-direct {v3, v7, v2, v9, v8}, Llyiahf/vczjk/n6;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    const v2, 0x6149a832

    invoke-static {v2, v3, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v16

    const/4 v15, 0x0

    const/16 v19, 0x7f8

    const-wide/16 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    const/16 v18, 0x0

    move-object/from16 v17, v1

    invoke-static/range {v4 .. v19}, Llyiahf/vczjk/fe;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
