.class public final Llyiahf/vczjk/f4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo0:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;JJJJLlyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/f4;->OooOOO0:Llyiahf/vczjk/ze3;

    iput-object p2, p0, Llyiahf/vczjk/f4;->OooOOO:Llyiahf/vczjk/a91;

    iput-wide p5, p0, Llyiahf/vczjk/f4;->OooOOOO:J

    iput-wide p7, p0, Llyiahf/vczjk/f4;->OooOOOo:J

    iput-wide p9, p0, Llyiahf/vczjk/f4;->OooOOo0:J

    iput-object p11, p0, Llyiahf/vczjk/f4;->OooOOo:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v3

    :goto_0
    and-int/2addr p2, v2

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_9

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object p2, Llyiahf/vczjk/j4;->OooO0o0:Llyiahf/vczjk/di6;

    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v0, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {p2, v0, v8, v3}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object p2

    iget v0, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v1

    invoke-static {v8, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v4, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_1

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {p2, v8, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v1, v8, p2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_3

    :cond_2
    invoke-static {v0, v8, v0, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, v8, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const p1, 0x14a0f326

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object p1, p0, Llyiahf/vczjk/f4;->OooOOO0:Llyiahf/vczjk/ze3;

    if-nez p1, :cond_4

    const p1, 0x14a59752

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    :goto_2
    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_4
    const v4, 0x14a59753

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Llyiahf/vczjk/bb2;->OooO0o:Llyiahf/vczjk/p6a;

    invoke-static {v4, v8}, Llyiahf/vczjk/q6a;->OooO00o(Llyiahf/vczjk/p6a;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/rn9;

    move-result-object v6

    new-instance v4, Llyiahf/vczjk/d4;

    const/4 v5, 0x0

    invoke-direct {v4, p1, v5}, Llyiahf/vczjk/d4;-><init>(Llyiahf/vczjk/ze3;I)V

    const p1, 0x43fb671

    invoke-static {p1, v4, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    const/16 v9, 0x180

    iget-wide v4, p0, Llyiahf/vczjk/f4;->OooOOOO:J

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_2

    :goto_3
    iget-object p1, p0, Llyiahf/vczjk/f4;->OooOOO:Llyiahf/vczjk/a91;

    if-nez p1, :cond_5

    const p1, 0x14b1707a

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    :goto_4
    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_5

    :cond_5
    const v4, 0x14b1707b

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Llyiahf/vczjk/bb2;->OooO0oo:Llyiahf/vczjk/p6a;

    invoke-static {v4, v8}, Llyiahf/vczjk/q6a;->OooO00o(Llyiahf/vczjk/p6a;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/rn9;

    move-result-object v6

    new-instance v4, Llyiahf/vczjk/e4;

    const/4 v5, 0x0

    invoke-direct {v4, p1, v5}, Llyiahf/vczjk/e4;-><init>(Llyiahf/vczjk/a91;I)V

    const p1, 0x2a0e58f2

    invoke-static {p1, v4, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    const/16 v9, 0x180

    iget-wide v4, p0, Llyiahf/vczjk/f4;->OooOOOo:J

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_4

    :goto_5
    sget-object p1, Llyiahf/vczjk/op3;->OooOoo0:Llyiahf/vczjk/sb0;

    new-instance v4, Landroidx/compose/foundation/layout/HorizontalAlignElement;

    invoke-direct {v4, p1}, Landroidx/compose/foundation/layout/HorizontalAlignElement;-><init>(Llyiahf/vczjk/sb0;)V

    sget-object p1, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {p1, v3}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object p1

    iget v3, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v8, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_6

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_6
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {p1, v8, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v5, v8, p2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean p1, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez p1, :cond_7

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_8

    :cond_7
    invoke-static {v3, v8, v3, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    invoke-static {v4, v8, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p1, Llyiahf/vczjk/bb2;->OooO0O0:Llyiahf/vczjk/p6a;

    invoke-static {p1, v8}, Llyiahf/vczjk/q6a;->OooO00o(Llyiahf/vczjk/p6a;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/rn9;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/f4;->OooOOo:Llyiahf/vczjk/a91;

    const/4 v9, 0x0

    iget-wide v4, p0, Llyiahf/vczjk/f4;->OooOOo0:J

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/tp6;->OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_7

    :cond_9
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_7
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
