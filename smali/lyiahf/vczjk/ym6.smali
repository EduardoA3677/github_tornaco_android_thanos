.class public final Llyiahf/vczjk/ym6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/w26;

.field public OooOOO0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w26;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ym6;->OooOOO:Llyiahf/vczjk/w26;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/ym6;->OooOOO0:Z

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/k41;

    const-string v0, "loadStates"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, p0, Llyiahf/vczjk/ym6;->OooOOO0:Z

    if-eqz v0, :cond_0

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/ym6;->OooOOO0:Z

    goto :goto_0

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/k41;->OooO0Oo:Llyiahf/vczjk/r25;

    iget-object p1, p1, Llyiahf/vczjk/r25;->OooO00o:Llyiahf/vczjk/q25;

    instance-of p1, p1, Llyiahf/vczjk/p25;

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/ym6;->OooOOO:Llyiahf/vczjk/w26;

    invoke-static {p1}, Llyiahf/vczjk/w26;->OooOO0o(Llyiahf/vczjk/w26;)V

    iget-object p1, p1, Llyiahf/vczjk/w26;->OooO0o0:Llyiahf/vczjk/v00;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p1, Llyiahf/vczjk/v00;->OooOO0:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p1, Llyiahf/vczjk/v00;->OooO:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/v00;->OooO0o:Llyiahf/vczjk/r00;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/kn6;->OooO0o0:Llyiahf/vczjk/hr5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/hr5;->OooO00o:Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {p1, v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
