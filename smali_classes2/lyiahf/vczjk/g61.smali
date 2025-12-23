.class public final Llyiahf/vczjk/g61;
.super Llyiahf/vczjk/t51;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/i88;

.field public final OooOOO0:Llyiahf/vczjk/t51;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t51;Llyiahf/vczjk/i88;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g61;->OooOOO0:Llyiahf/vczjk/t51;

    iput-object p2, p0, Llyiahf/vczjk/g61;->OooOOO:Llyiahf/vczjk/i88;

    return-void
.end method


# virtual methods
.method public final Ooooo0o(Llyiahf/vczjk/d61;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/f61;

    iget-object v1, p0, Llyiahf/vczjk/g61;->OooOOO0:Llyiahf/vczjk/t51;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/f61;-><init>(Llyiahf/vczjk/d61;Llyiahf/vczjk/t51;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/d61;->OooO0O0(Llyiahf/vczjk/nc2;)V

    iget-object p1, p0, Llyiahf/vczjk/g61;->OooOOO:Llyiahf/vczjk/i88;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/i88;->OooO0O0(Ljava/lang/Runnable;)Llyiahf/vczjk/nc2;

    move-result-object p1

    iget-object v0, v0, Llyiahf/vczjk/f61;->task:Llyiahf/vczjk/eg8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, p1}, Llyiahf/vczjk/tc2;->OooO0OO(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method
