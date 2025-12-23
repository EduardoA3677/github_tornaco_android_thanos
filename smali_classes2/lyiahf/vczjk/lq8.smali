.class public final Llyiahf/vczjk/lq8;
.super Llyiahf/vczjk/jp8;
.source "SourceFile"


# instance fields
.field public final OooOo:Llyiahf/vczjk/i88;

.field public final synthetic OooOo0O:I

.field public final OooOo0o:Llyiahf/vczjk/jp8;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/jp8;Llyiahf/vczjk/i88;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/lq8;->OooOo0O:I

    iput-object p1, p0, Llyiahf/vczjk/lq8;->OooOo0o:Llyiahf/vczjk/jp8;

    iput-object p2, p0, Llyiahf/vczjk/lq8;->OooOo:Llyiahf/vczjk/i88;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OoooOOO(Llyiahf/vczjk/tp8;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/lq8;->OooOo0O:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/sp8;

    iget-object v1, p0, Llyiahf/vczjk/lq8;->OooOo:Llyiahf/vczjk/i88;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/sp8;-><init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/i88;)V

    iget-object p1, p0, Llyiahf/vczjk/lq8;->OooOo0o:Llyiahf/vczjk/jp8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/jp8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/kq8;

    iget-object v1, p0, Llyiahf/vczjk/lq8;->OooOo0o:Llyiahf/vczjk/jp8;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/kq8;-><init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/jp8;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    iget-object p1, p0, Llyiahf/vczjk/lq8;->OooOo:Llyiahf/vczjk/i88;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/i88;->OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;

    move-result-object p1

    iget-object v0, v0, Llyiahf/vczjk/kq8;->task:Llyiahf/vczjk/eg8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, p1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
