.class public final Llyiahf/vczjk/ta9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:Z

.field public final synthetic OooOOo0:Llyiahf/vczjk/se0;

.field public final synthetic OooOOoo:Llyiahf/vczjk/rr5;

.field public final synthetic OooOo0:Llyiahf/vczjk/oe3;

.field public final synthetic OooOo00:Z

.field public final synthetic OooOo0O:F

.field public final synthetic OooOo0o:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JFLlyiahf/vczjk/se0;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/oe3;FLlyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ta9;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/ta9;->OooOOO:Llyiahf/vczjk/qj8;

    iput-wide p3, p0, Llyiahf/vczjk/ta9;->OooOOOO:J

    iput p5, p0, Llyiahf/vczjk/ta9;->OooOOOo:F

    iput-object p6, p0, Llyiahf/vczjk/ta9;->OooOOo0:Llyiahf/vczjk/se0;

    iput-boolean p7, p0, Llyiahf/vczjk/ta9;->OooOOo:Z

    iput-object p8, p0, Llyiahf/vczjk/ta9;->OooOOoo:Llyiahf/vczjk/rr5;

    iput-boolean p9, p0, Llyiahf/vczjk/ta9;->OooOo00:Z

    iput-object p10, p0, Llyiahf/vczjk/ta9;->OooOo0:Llyiahf/vczjk/oe3;

    iput p11, p0, Llyiahf/vczjk/ta9;->OooOo0O:F

    iput-object p12, p0, Llyiahf/vczjk/ta9;->OooOo0o:Llyiahf/vczjk/a91;

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

    and-int/lit8 v3, v2, 0x3

    const/4 v4, 0x0

    const/4 v5, 0x2

    const/4 v6, 0x1

    if-eq v3, v5, :cond_0

    move v3, v6

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    and-int/2addr v2, v6

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_4

    sget-object v2, Llyiahf/vczjk/r24;->OooO00o:Llyiahf/vczjk/go3;

    sget-object v2, Landroidx/compose/material3/MinimumInteractiveModifier;->OooOOO0:Landroidx/compose/material3/MinimumInteractiveModifier;

    iget-object v3, v0, Llyiahf/vczjk/ta9;->OooOOO0:Llyiahf/vczjk/kl5;

    invoke-interface {v3, v2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    iget-wide v2, v0, Llyiahf/vczjk/ta9;->OooOOOO:J

    iget v5, v0, Llyiahf/vczjk/ta9;->OooOOOo:F

    invoke-static {v2, v3, v5, v1}, Llyiahf/vczjk/ua9;->OooO0o0(JFLlyiahf/vczjk/zf1;)J

    move-result-wide v9

    sget-object v2, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    iget v3, v0, Llyiahf/vczjk/ta9;->OooOo0O:F

    check-cast v2, Llyiahf/vczjk/f62;

    invoke-interface {v2, v3}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v12

    iget-object v8, v0, Llyiahf/vczjk/ta9;->OooOOO:Llyiahf/vczjk/qj8;

    iget-object v11, v0, Llyiahf/vczjk/ta9;->OooOOo0:Llyiahf/vczjk/se0;

    invoke-static/range {v7 .. v12}, Llyiahf/vczjk/ua9;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JLlyiahf/vczjk/se0;F)Llyiahf/vczjk/kl5;

    move-result-object v13

    const/4 v2, 0x0

    const/4 v3, 0x7

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/zt7;->OooO00o(FIZ)Llyiahf/vczjk/du7;

    move-result-object v16

    iget-object v15, v0, Llyiahf/vczjk/ta9;->OooOOoo:Llyiahf/vczjk/rr5;

    iget-boolean v2, v0, Llyiahf/vczjk/ta9;->OooOo00:Z

    iget-boolean v14, v0, Llyiahf/vczjk/ta9;->OooOOo:Z

    const/16 v18, 0x0

    iget-object v3, v0, Llyiahf/vczjk/ta9;->OooOo0:Llyiahf/vczjk/oe3;

    move/from16 v17, v2

    move-object/from16 v19, v3

    invoke-static/range {v13 .. v19}, Landroidx/compose/foundation/selection/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/du7;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/cp7;->OooO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v3, v6}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v5, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_1

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_3

    :cond_2
    invoke-static {v5, v1, v5, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/ta9;->OooOo0o:Llyiahf/vczjk/a91;

    invoke-virtual {v3, v1, v2}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_2

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
