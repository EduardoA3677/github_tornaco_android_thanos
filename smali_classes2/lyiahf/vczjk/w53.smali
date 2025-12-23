.class public final Llyiahf/vczjk/w53;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/f43;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/eb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/w53;->OooOOO0:I

    packed-switch p3, :pswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w53;->OooOOO:Llyiahf/vczjk/f43;

    check-cast p2, Llyiahf/vczjk/eb9;

    iput-object p2, p0, Llyiahf/vczjk/w53;->OooOOOO:Llyiahf/vczjk/eb9;

    return-void

    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w53;->OooOOO:Llyiahf/vczjk/f43;

    check-cast p2, Llyiahf/vczjk/eb9;

    iput-object p2, p0, Llyiahf/vczjk/w53;->OooOOOO:Llyiahf/vczjk/eb9;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/w53;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/t63;

    iget-object v1, p0, Llyiahf/vczjk/w53;->OooOOOO:Llyiahf/vczjk/eb9;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/t63;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/ze3;)V

    iget-object p1, p0, Llyiahf/vczjk/w53;->OooOOO:Llyiahf/vczjk/f43;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/dl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/y53;

    iget-object v2, p0, Llyiahf/vczjk/w53;->OooOOOO:Llyiahf/vczjk/eb9;

    invoke-direct {v1, v0, p1, v2}, Llyiahf/vczjk/y53;-><init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/h43;Llyiahf/vczjk/ze3;)V

    iget-object p1, p0, Llyiahf/vczjk/w53;->OooOOO:Llyiahf/vczjk/f43;

    invoke-interface {p1, v1, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
