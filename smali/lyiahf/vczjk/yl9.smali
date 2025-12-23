.class public final Llyiahf/vczjk/yl9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tl9;

.field public final OooO0O0:Llyiahf/vczjk/tx6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tl9;Llyiahf/vczjk/tx6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yl9;->OooO00o:Llyiahf/vczjk/tl9;

    iput-object p2, p0, Llyiahf/vczjk/yl9;->OooO0O0:Llyiahf/vczjk/tx6;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/gl9;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yl9;->OooO00o:Llyiahf/vczjk/tl9;

    iget-object v0, v0, Llyiahf/vczjk/tl9;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/yl9;

    invoke-static {v0, p0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/yl9;->OooO0O0:Llyiahf/vczjk/tx6;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/tx6;->OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/gl9;)V

    :cond_0
    return-void
.end method
