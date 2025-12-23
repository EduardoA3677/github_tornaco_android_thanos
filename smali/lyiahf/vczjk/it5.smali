.class public final Llyiahf/vczjk/it5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/util/concurrent/atomic/AtomicReference;

.field public final OooO0O0:Llyiahf/vczjk/mt5;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/it5;->OooO00o:Ljava/util/concurrent/atomic/AtomicReference;

    new-instance v0, Llyiahf/vczjk/mt5;

    invoke-direct {v0}, Llyiahf/vczjk/mt5;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/it5;->OooO0O0:Llyiahf/vczjk/mt5;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/it5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/bt5;->OooOOO0:Llyiahf/vczjk/bt5;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/ft5;

    const/4 v2, 0x0

    invoke-direct {v1, v0, p0, p1, v2}, Llyiahf/vczjk/ft5;-><init>(Llyiahf/vczjk/bt5;Llyiahf/vczjk/it5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method
