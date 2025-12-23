.class public final synthetic Llyiahf/vczjk/i5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/ki2;


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/xr1;Llyiahf/vczjk/ki2;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/i5;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/i5;->OooOOO:Llyiahf/vczjk/xr1;

    iput-object p3, p0, Llyiahf/vczjk/i5;->OooOOOO:Llyiahf/vczjk/ki2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/ki2;Llyiahf/vczjk/xr1;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Llyiahf/vczjk/i5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i5;->OooOOOO:Llyiahf/vczjk/ki2;

    iput-object p2, p0, Llyiahf/vczjk/i5;->OooOOO:Llyiahf/vczjk/xr1;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/i5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/th8;

    iget-object v1, p0, Llyiahf/vczjk/i5;->OooOOOO:Llyiahf/vczjk/ki2;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/th8;-><init>(Llyiahf/vczjk/ki2;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/i5;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/i5;->OooOOOO:Llyiahf/vczjk/ki2;

    iget-object v1, v0, Llyiahf/vczjk/ki2;->OooO0O0:Llyiahf/vczjk/c9;

    iget-object v1, v1, Llyiahf/vczjk/c9;->OooO0Oo:Llyiahf/vczjk/oe3;

    sget-object v2, Llyiahf/vczjk/mi2;->OooOOO0:Llyiahf/vczjk/mi2;

    invoke-interface {v1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, Llyiahf/vczjk/wx5;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/wx5;-><init>(Llyiahf/vczjk/ki2;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    iget-object v3, p0, Llyiahf/vczjk/i5;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_0
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/mw5;

    iget-object v1, p0, Llyiahf/vczjk/i5;->OooOOOO:Llyiahf/vczjk/ki2;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/mw5;-><init>(Llyiahf/vczjk/ki2;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/i5;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/ba5;

    iget-object v1, p0, Llyiahf/vczjk/i5;->OooOOOO:Llyiahf/vczjk/ki2;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ba5;-><init>(Llyiahf/vczjk/ki2;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/i5;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/j5;

    iget-object v1, p0, Llyiahf/vczjk/i5;->OooOOOO:Llyiahf/vczjk/ki2;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/j5;-><init>(Llyiahf/vczjk/ki2;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/i5;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
