.class public final synthetic Llyiahf/vczjk/s20;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/lg0;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;Llyiahf/vczjk/lg0;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/s20;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/s20;->OooOOO:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/s20;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/s20;->OooOOOo:Llyiahf/vczjk/lg0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/s20;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/s20;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/g08;

    iget-object v1, p0, Llyiahf/vczjk/s20;->OooOOOo:Llyiahf/vczjk/lg0;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/g08;-><init>(Llyiahf/vczjk/lg0;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/s20;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v0}, Llyiahf/vczjk/im4;->OooO00o()V

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/s20;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_1

    new-instance v0, Llyiahf/vczjk/t20;

    iget-object v1, p0, Llyiahf/vczjk/s20;->OooOOOo:Llyiahf/vczjk/lg0;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/t20;-><init>(Llyiahf/vczjk/lg0;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v3, p0, Llyiahf/vczjk/s20;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v3, v2, v2, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_1

    :cond_1
    sget-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v0}, Llyiahf/vczjk/im4;->OooO00o()V

    :goto_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
