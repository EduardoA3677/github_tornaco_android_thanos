.class public final Llyiahf/vczjk/np8;
.super Llyiahf/vczjk/jp8;
.source "SourceFile"


# instance fields
.field public final OooOo:Ljava/lang/Object;

.field public final synthetic OooOo0O:I

.field public final OooOo0o:Llyiahf/vczjk/jp8;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/jp8;Ljava/lang/Object;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/np8;->OooOo0O:I

    iput-object p1, p0, Llyiahf/vczjk/np8;->OooOo0o:Llyiahf/vczjk/jp8;

    iput-object p2, p0, Llyiahf/vczjk/np8;->OooOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OoooOOO(Llyiahf/vczjk/tp8;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/np8;->OooOo0O:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/bp8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/bp8;-><init>(Llyiahf/vczjk/np8;Llyiahf/vczjk/tp8;)V

    iget-object p1, p0, Llyiahf/vczjk/np8;->OooOo0o:Llyiahf/vczjk/jp8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jp8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/wg7;

    iget-object v1, p0, Llyiahf/vczjk/np8;->OooOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/oOO0O00O;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/wg7;-><init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/oOO0O00O;)V

    iget-object p1, p0, Llyiahf/vczjk/np8;->OooOo0o:Llyiahf/vczjk/jp8;

    check-cast p1, Llyiahf/vczjk/lp8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jp8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    return-void

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/qx7;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/qx7;-><init>(Llyiahf/vczjk/np8;Llyiahf/vczjk/tp8;)V

    iget-object p1, p0, Llyiahf/vczjk/np8;->OooOo0o:Llyiahf/vczjk/jp8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jp8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    return-void

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/xo8;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object p0, v0, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/xo8;->OooOOO0:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/np8;->OooOo0o:Llyiahf/vczjk/jp8;

    check-cast p1, Llyiahf/vczjk/oq8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jp8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
