.class public final synthetic Llyiahf/vczjk/w20;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/i40;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/i40;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/w20;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/w20;->OooOOO:Llyiahf/vczjk/i40;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/w20;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/w20;->OooOOO:Llyiahf/vczjk/i40;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/v30;

    const/4 v3, 0x0

    invoke-direct {v2, v0, p1, v3}, Llyiahf/vczjk/v30;-><init>(Llyiahf/vczjk/i40;ZLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/w20;->OooOOO:Llyiahf/vczjk/i40;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/u30;

    const/4 v3, 0x0

    invoke-direct {v2, v0, p1, v3}, Llyiahf/vczjk/u30;-><init>(Llyiahf/vczjk/i40;ZLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/mw;

    const-string p1, "it"

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/w20;->OooOOO:Llyiahf/vczjk/i40;

    :cond_0
    iget-object p1, v1, Llyiahf/vczjk/i40;->OooO0oO:Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/q30;

    const/16 v4, 0x17

    const/4 v5, 0x0

    invoke-static {v3, v5, v5, v0, v4}, Llyiahf/vczjk/q30;->OooO00o(Llyiahf/vczjk/q30;Ljava/util/List;Llyiahf/vczjk/mw;Llyiahf/vczjk/mw;I)Llyiahf/vczjk/q30;

    move-result-object v3

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/mw;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/w20;->OooOOO:Llyiahf/vczjk/i40;

    :cond_1
    iget-object v1, v0, Llyiahf/vczjk/i40;->OooO0oO:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/q30;

    const/16 v4, 0x1d

    const/4 v5, 0x0

    invoke-static {v3, v5, p1, v5, v4}, Llyiahf/vczjk/q30;->OooO00o(Llyiahf/vczjk/q30;Ljava/util/List;Llyiahf/vczjk/mw;Llyiahf/vczjk/mw;I)Llyiahf/vczjk/q30;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
