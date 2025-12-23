.class public final Llyiahf/vczjk/iw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/di6;

.field public final synthetic OooOOO0:F

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/di6;JLlyiahf/vczjk/a91;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/iw0;->OooOOO0:F

    iput-object p2, p0, Llyiahf/vczjk/iw0;->OooOOO:Llyiahf/vczjk/di6;

    iput-object p5, p0, Llyiahf/vczjk/iw0;->OooOOOO:Llyiahf/vczjk/a91;

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

    const/4 v1, 0x0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eq v0, v3, :cond_0

    move v0, v4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    and-int/2addr p2, v4

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_8

    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v0, 0x0

    iget v3, p0, Llyiahf/vczjk/iw0;->OooOOO0:F

    invoke-static {p2, v0, v3, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0O0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v0

    iget-object v3, p0, Llyiahf/vczjk/iw0;->OooOOO:Llyiahf/vczjk/di6;

    invoke-static {v0, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v5, :cond_1

    new-instance v3, Llyiahf/vczjk/lw0;

    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v3, Llyiahf/vczjk/lw0;

    iget v5, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {p1, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_2

    invoke-virtual {p1, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, p1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, p1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_4

    :cond_3
    invoke-static {v5, p1, v5, v6}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v0, -0x187750ed

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const-string v0, "label"

    invoke-static {p2, v0}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget v0, Llyiahf/vczjk/jw0;->OooO00o:F

    int-to-float v9, v1

    invoke-static {p2, v0, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v9, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v10, 0x36

    invoke-static {v0, v9, p1, v10}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v9, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_5

    invoke-virtual {p1, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    invoke-static {v0, p1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v10, p1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7

    :cond_6
    invoke-static {v9, p1, v9, v6}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    invoke-static {p2, p1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object p2, p0, Llyiahf/vczjk/iw0;->OooOOOO:Llyiahf/vczjk/a91;

    invoke-virtual {p2, p1, v2}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const p2, -0x1869dfed

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_8
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
