.class public final Llyiahf/vczjk/cz8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/di6;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/cz8;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/cz8;->OooOOO:Llyiahf/vczjk/di6;

    iput-object p2, p0, Llyiahf/vczjk/cz8;->OooOOOO:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/cz8;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_4

    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget v0, Llyiahf/vczjk/zs9;->OooO00o:F

    const/4 v1, 0x0

    invoke-static {p2, v1, v0, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0O0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/cz8;->OooOOO:Llyiahf/vczjk/di6;

    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v1, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v3, 0x36

    invoke-static {v0, v1, p1, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v1, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_1

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_3

    :cond_2
    invoke-static {v1, p1, v1, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    const/4 v0, 0x6

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/cz8;->OooOOOO:Llyiahf/vczjk/a91;

    invoke-virtual {v1, p2, p1, v0}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_2

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_5

    move v0, v2

    goto :goto_3

    :cond_5
    const/4 v0, 0x0

    :goto_3
    and-int/2addr p2, v2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_9

    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget v0, Llyiahf/vczjk/fz8;->OooOoO0:F

    sget v1, Llyiahf/vczjk/fz8;->OooOoO:F

    invoke-static {p2, v0, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooO00o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/cz8;->OooOOO:Llyiahf/vczjk/di6;

    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v1, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v3, 0x36

    invoke-static {v0, v1, p1, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v1, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_6

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_8

    :cond_7
    invoke-static {v1, p1, v1, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    const/4 v0, 0x6

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/cz8;->OooOOOO:Llyiahf/vczjk/a91;

    invoke-virtual {v1, p2, p1, v0}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_5

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
