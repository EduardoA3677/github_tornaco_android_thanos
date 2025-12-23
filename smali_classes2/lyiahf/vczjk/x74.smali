.class public Llyiahf/vczjk/x74;
.super Llyiahf/vczjk/k84;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/b61;


# instance fields
.field public final OooOOOO:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v74;)V
    .locals 5

    const/4 v0, 0x1

    invoke-direct {p0, v0}, Llyiahf/vczjk/k84;-><init>(Z)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/k84;->Oooo0O0(Llyiahf/vczjk/v74;)V

    sget-object p1, Llyiahf/vczjk/k84;->OooOOO:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ov0;

    instance-of v2, v1, Llyiahf/vczjk/pv0;

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/pv0;

    goto :goto_0

    :cond_0
    move-object v1, v3

    :goto_0
    const/4 v2, 0x0

    if-eqz v1, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/f84;->OooOO0()Llyiahf/vczjk/k84;

    move-result-object v1

    :goto_1
    invoke-virtual {v1}, Llyiahf/vczjk/k84;->OooOooO()Z

    move-result v4

    if-eqz v4, :cond_1

    goto :goto_3

    :cond_1
    invoke-virtual {p1, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ov0;

    instance-of v4, v1, Llyiahf/vczjk/pv0;

    if-eqz v4, :cond_2

    check-cast v1, Llyiahf/vczjk/pv0;

    goto :goto_2

    :cond_2
    move-object v1, v3

    :goto_2
    if-eqz v1, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/f84;->OooOO0()Llyiahf/vczjk/k84;

    move-result-object v1

    goto :goto_1

    :cond_3
    move v0, v2

    :goto_3
    iput-boolean v0, p0, Llyiahf/vczjk/x74;->OooOOOO:Z

    return-void
.end method


# virtual methods
.method public final OooOooO()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/x74;->OooOOOO:Z

    return v0
.end method

.method public final Oooo000()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method
