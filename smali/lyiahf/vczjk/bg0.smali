.class public final synthetic Llyiahf/vczjk/bg0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/zl8;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/zl8;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/bg0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/bg0;->OooOOO:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/bg0;->OooOOOO:Llyiahf/vczjk/zl8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/xr1;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/bg0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/bg0;->OooOOOO:Llyiahf/vczjk/zl8;

    iput-object p2, p0, Llyiahf/vczjk/bg0;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/bg0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/bg0;->OooOOOO:Llyiahf/vczjk/zl8;

    iget-object v1, v0, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v1, v1, Llyiahf/vczjk/c9;->OooO0Oo:Llyiahf/vczjk/oe3;

    sget-object v2, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    invoke-interface {v1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, Llyiahf/vczjk/sk5;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/sk5;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    iget-object v3, p0, Llyiahf/vczjk/bg0;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_0
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/bg0;->OooOOOO:Llyiahf/vczjk/zl8;

    invoke-virtual {v0}, Llyiahf/vczjk/zl8;->OooO0OO()Llyiahf/vczjk/am8;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    const/4 v2, 0x1

    const/4 v3, 0x3

    const/4 v4, 0x0

    iget-object v5, p0, Llyiahf/vczjk/bg0;->OooOOO:Llyiahf/vczjk/xr1;

    if-eq v1, v2, :cond_2

    const/4 v2, 0x2

    if-eq v1, v2, :cond_1

    new-instance v1, Llyiahf/vczjk/fg0;

    invoke-direct {v1, v0, v4}, Llyiahf/vczjk/fg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    invoke-static {v5, v4, v4, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_0

    :cond_1
    new-instance v1, Llyiahf/vczjk/eg0;

    invoke-direct {v1, v0, v4}, Llyiahf/vczjk/eg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    invoke-static {v5, v4, v4, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_0

    :cond_2
    new-instance v1, Llyiahf/vczjk/dg0;

    invoke-direct {v1, v0, v4}, Llyiahf/vczjk/dg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    invoke-static {v5, v4, v4, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/ig0;

    iget-object v1, p0, Llyiahf/vczjk/bg0;->OooOOOO:Llyiahf/vczjk/zl8;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ig0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/bg0;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/hg0;

    iget-object v1, p0, Llyiahf/vczjk/bg0;->OooOOOO:Llyiahf/vczjk/zl8;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/hg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/bg0;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/gg0;

    iget-object v1, p0, Llyiahf/vczjk/bg0;->OooOOOO:Llyiahf/vczjk/zl8;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/gg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/bg0;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
